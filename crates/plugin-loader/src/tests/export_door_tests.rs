// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, OnceLock};

use busbar_contract::abi::export::ExportStream;
use busbar_contract::export_calls::{parse_families, ServeRequest};

use super::*;
use crate::dispatch::{load_linked, Bind, DispatchConfig, LinkedRow, NoSink};

pub(crate) const SCRAPE_DOOR: busbar_contract::abi::mechanism::door::DoorFn = scrape_door;

extern "C" fn scrape_door() -> &'static busbar_contract::abi::mechanism::door::Door {
    use busbar_contract::abi::mechanism::DOOR_SYMBOL;
    use busbar_contract::abi::sdk::door::RawDoorFn;
    static IMAGE: OnceLock<(libloading::Library, RawDoorFn)> = OnceLock::new();
    let image = IMAGE.get_or_init(|| {
        let path = std::env::var_os("BUSBAR_TEST_EXPORT_PROMETHEUS_CDYLIB")
            .map(std::path::PathBuf::from)
            .expect(
                "BUSBAR_TEST_EXPORT_PROMETHEUS_CDYLIB must name the fresh actual Prometheus image",
            );
        assert!(
            path.is_absolute() && path.is_file(),
            "the actual Prometheus image must be an absolute file: {}",
            path.display()
        );
        let library = crate::dlopen_on_worker(path.as_os_str())
            .expect("the actual Prometheus image loads on the plugin thread");
        // SAFETY: the selected product image exports the mechanism's typed symbol.
        // IMAGE retains the library while its immutable descriptor and code are used.
        let entry = unsafe {
            *library
                .get::<RawDoorFn>(DOOR_SYMBOL)
                .expect("the actual Prometheus door")
        };
        (library, entry)
    });
    let door = crate::dispatch::load::enter_door(image.1);
    crate::dispatch::load::validate_door::<Export>(door)
        .expect("the actual Prometheus descriptor validates");
    // SAFETY: the validated descriptor is immutable and IMAGE keeps its library alive.
    unsafe { &*door }
}

fn linked() -> (Plugin<Export>, Arc<Dispatcher>) {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(SCRAPE_DOOR).expect("the door states itself");
    let bind = Bind {
        instance: Arc::from("export.metrics"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: crate::dispatch::ConnTable::Host(crate::actual_exports::prometheus_inbound::table()),
    };
    let plugin = load_linked::<Export>(&row, bind).expect("the linked door loads");
    (plugin, dispatcher)
}

#[test]
fn the_tail_is_read_at_bind() {
    let (plugin, _) = linked();
    let facts = plugin.context::<ExportFacts>().expect("an export tail");
    assert_eq!(facts.streams, vec![ExportStream::Metrics as u8]);
    let routes: Vec<String> = facts
        .routes
        .iter()
        .map(|r| format!("{} {} {:?}", r.method.as_str(), r.path, r.auth))
        .collect();
    assert_eq!(
        routes,
        ["GET /metrics Key", "GET /metrics/hooks Key"],
        "the scrape sink declares its own two well-known routes"
    );
}

#[test]
fn listener_policy_is_copied_from_the_statement_into_the_opened_sink() {
    let (plugin, dispatcher) = linked();
    let facts = plugin.context::<ExportFacts>().unwrap();
    assert_eq!(facts.public_routes, ["/metrics", "/metrics/hooks"]);
    assert_eq!(facts.persistent_routes, ["/metrics/hooks"]);
    let sink = ExportInstance::open(plugin, dispatcher, br#"{"buffer_seconds":60}"#).unwrap();
    assert_eq!(sink.public_routes(), ["/metrics", "/metrics/hooks"]);
    assert_eq!(sink.persistent_routes(), ["/metrics/hooks"]);
}

#[test]
fn listener_policy_rejects_undeclared_and_non_public_persistent_paths() {
    use busbar_contract::abi::mechanism::extensions::{encode, statement_blob};
    for (public, persistent) in [
        (br#"["/not-declared"]"#.as_slice(), br#"[]"#.as_slice()),
        (br#"[]"#.as_slice(), br#"["/metrics/hooks"]"#.as_slice()),
        (
            br#"["/metrics","/metrics"]"#.as_slice(),
            br#"[]"#.as_slice(),
        ),
        (br#"false"#.as_slice(), br#"[]"#.as_slice()),
    ] {
        let bytes = Box::leak(
            encode(&[
                ("listener.public_routes", public),
                ("listener.persistent_routes", persistent),
            ])
            .into_boxed_slice(),
        );
        // SAFETY: the fixture door's Statement lives for the process.
        let mut statement = unsafe { *SCRAPE_DOOR().statement() };
        statement.extensions = statement_blob(bytes);
        assert!(<Export as crate::dispatch::Kind>::context(&statement).is_err());
    }
}

#[test]
fn settings_the_sink_refuses_never_open() {
    let (plugin, dispatcher) = linked();
    let refused = ExportInstance::open(plugin, dispatcher, br#"{"bogus":1}"#)
        .expect_err("refused settings do not open");
    assert!(
        refused.starts_with("settings: unknown field `bogus`"),
        "{refused}"
    );
}

#[test]
fn a_scrape_renders_the_snapshot_and_a_short_answer_is_re_called_once() {
    let (plugin, dispatcher) = linked();
    let sink = ExportInstance::open(plugin, dispatcher, br#"{"buffer_seconds":60}"#)
        .expect("the sink opens");

    let mut text = String::from("# TYPE busbar_big counter\n");
    for i in 0..4000 {
        text.push_str(&format!("busbar_big{{n=\"{i:020}\"}} {i}\n"));
    }
    text.push('\n');
    assert!(text.len() > SCRAPE_BUF);
    let families = parse_families(&text).expect("the snapshot reads");
    let body = sink.scrape(&families).expect("the sink renders");
    assert_eq!(body, text.as_bytes());
    assert_eq!(sink.scrape(&[]).expect("an empty snapshot"), b"");
}

#[test]
fn a_hook_scrape_carries_its_flag_through_the_call_and_the_re_call() {
    let (plugin, dispatcher) = linked();
    let sink = ExportInstance::open(plugin, dispatcher, br#"{"buffer_seconds":60}"#)
        .expect("the sink opens");
    let mut big = String::from("# TYPE big_total counter\n");
    for i in 0..4000 {
        big.push_str(&format!("big_total{{hook=\"h\",n=\"{i:020}\"}} {i}\n"));
    }
    let small = "# TYPE small gauge\nsmall{hook=\"h\"} 1\n";
    let text = format!("{big}{small}");
    assert!(text.len() > SCRAPE_BUF);
    let mut families = parse_families(&format!("{big}\n{small}\n")).expect("the families read");
    families.reverse();
    let body = sink
        .scrape_hooks(&families)
        .expect("the sink renders hook families");
    assert_eq!(String::from_utf8_lossy(&body), text);
    let plain = sink
        .scrape(&families)
        .expect("the sink renders the snapshot");
    assert!(
        String::from_utf8_lossy(&plain).contains("\n\n"),
        "without the flag: /metrics' layout"
    );
}

#[test]
fn the_ops_the_sink_does_not_serve_are_answered_as_such() {
    let (plugin, dispatcher) = linked();
    let sink = ExportInstance::open(plugin, dispatcher, br#"{"buffer_seconds":60}"#)
        .expect("the sink opens");
    assert_eq!(sink.status(), None);
    let req = ServeRequest {
        method: "GET",
        path: "/metrics",
        query: None,
        headers: &[],
        body: &[],
    };
    assert!(
        sink.serve(&req).is_err(),
        "with no host services bound the snapshot read is declined: an error, never bytes"
    );
    assert!(check(sink.plugin(), 1, &[])
        .expect("check answers")
        .is_empty());
}

#[test]
fn refresh_refusal_and_success_leave_the_opened_export_usable() {
    let (plugin, dispatcher) = linked();
    let sink = ExportInstance::open(plugin, dispatcher, br#"{"buffer_seconds":60}"#)
        .expect("the sink opens");
    for settings in [
        serde_json::json!({"bogus": 1}),
        serde_json::json!({"buffer_seconds": 0}),
        serde_json::json!({"buffer_seconds": "thirty"}),
    ] {
        assert!(sink.refresh(&settings, 2).is_err(), "{settings}");
        assert!(sink.plugin().is_open());
    }
    sink.refresh(&serde_json::json!({"buffer_seconds": 30}), 3)
        .expect("valid settings refresh the existing export");
    let text = "# TYPE private_counter counter\nprivate_counter{pool=\"private\"} 1\n\n";
    let families = parse_families(text).unwrap();
    assert_eq!(sink.scrape(&families).unwrap(), text.as_bytes());
    assert!(sink.plugin().is_open());
}

#[test]
fn a_dropped_instance_is_closed() {
    let (plugin, dispatcher) = linked();
    let sink = ExportInstance::open(plugin, dispatcher, br#"{"buffer_seconds":60}"#)
        .expect("the sink opens");
    let instance = Arc::clone(&sink.plugin().inner);
    assert!(instance.is_open());
    drop(sink);
    assert!(!instance.is_open(), "the dropped instance was never closed");
}

extern "C" fn stop_accounting_door() -> &'static busbar_contract::abi::mechanism::door::Door {
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    let door = SCRAPE_DOOR();
    // SAFETY: the real fixture publishes an immutable Statement for the process.
    let mut statement = unsafe { *door.statement() };
    statement.name = busbar_contract::abi::sdk::door::abi_str("export-stop-accounting");
    let statement = Box::leak(Box::new(statement));
    // SAFETY: only the test identity changes; the fixture's complete ABI table is preserved.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            statement,
            ..door.parts()
        })
    }))
}

struct QueueRelease {
    shared: std::sync::Weak<Shared>,
    observed: Arc<Mutex<Vec<bool>>>,
}

impl Drop for QueueRelease {
    fn drop(&mut self) {
        let unlocked = self
            .shared
            .upgrade()
            .is_some_and(|s| s.queue.try_lock().is_ok());
        self.observed.lock().unwrap().push(unlocked);
    }
}

#[test]
fn stopping_counts_queued_lines_and_releases_their_holds_outside_the_queue_lock() {
    let guard = crate::observe::testing::exclusive();
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load_linked::<Export>(
        &LinkedRow::of(stop_accounting_door).unwrap(),
        Bind {
            instance: Arc::from("export.stop-accounting"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: crate::dispatch::ConnTable::Host(
                crate::actual_exports::prometheus_inbound::table(),
            ),
        },
    )
    .unwrap();
    let opened = plugin.call(
        lc::OPEN,
        &mut open_frame(blob(br#"{"buffer_seconds":60}"#, BLOB_JSON)),
    );
    assert_eq!(opened.outcome, Outcome::Ready);
    let mut series = busbar_contract::abi::mechanism::observe::SeriesDecl::new(
        "busbar_export_stop_test_shed",
        "counter",
    );
    series.shed = true;
    let grant =
        crate::observe::grant_series(dispatcher.observing(), plugin.name(), true, &[series])
            .unwrap();
    let shared = Arc::new(Shared {
        facts: plugin.context::<ExportFacts>().unwrap().clone(),
        plugin,
        dispatcher,
        queue: Mutex::default(),
        flusher: Mutex::default(),
        stop: AtomicBool::new(false),
        abandon: AtomicBool::new(false),
        node: node_id(),
        minted: AtomicU64::new(0),
    });

    let sink = ExportInstance {
        shared: Arc::clone(&shared),
        flusher: Mutex::new(None),
        _grant: Some(grant),
    };
    let released = Arc::new(Mutex::new(Vec::new()));
    for line in [br#"{"line":1}"#.to_vec(), br#"{"line":2}"#.to_vec()] {
        assert_eq!(
            sink.deliver(
                ExportStream::Metrics as u8,
                line,
                Box::new(QueueRelease {
                    shared: Arc::downgrade(&shared),
                    observed: Arc::clone(&released)
                })
            ),
            Delivered::Queued
        );
    }
    crate::observe::testing::clear(&guard);
    shared.stop.store(true, Ordering::Release);
    Arc::clone(&shared).flush();
    assert_eq!(sink.queued(), 0);
    assert_eq!(
        *released.lock().unwrap(),
        vec![true, true],
        "both accepted holds released with queue unlocked"
    );
    let shed_total = || {
        crate::observe::testing::folds()
            .iter()
            .flat_map(|(_, _, metrics, _)| metrics)
            .filter(|metric| metric["name"] == "busbar_export_stop_test_shed")
            .map(|metric| metric["value"].as_u64().unwrap())
            .sum::<u64>()
    };
    assert_eq!(
        shed_total(),
        2,
        "every accepted but undelivered line is reported"
    );
    Arc::clone(&shared).flush();
    assert_eq!(
        shed_total(),
        2,
        "empty stop neither recounts nor fabricates a shed"
    );
    drop(sink);
}

/// A host I/O that holds nothing and records whose handles the host reaps.
#[derive(Default)]
struct Reaps(std::sync::Mutex<Vec<u64>>);

impl busbar_contract::io_host::IoHost for Reaps {
    fn open(
        &self,
        _: u64,
        _: busbar_contract::abi::mechanism::ticket::Ticket,
        _: &str,
    ) -> busbar_contract::io_host::IoResult<u64> {
        Err(busbar_contract::io_host::IoRefusal::unknown())
    }
    fn listen(
        &self,
        _: u64,
        _: busbar_contract::abi::mechanism::ticket::Ticket,
        _: &str,
    ) -> busbar_contract::io_host::IoResult<(u64, String)> {
        Err(busbar_contract::io_host::IoRefusal::unknown())
    }
    fn accept(
        &self,
        _: u64,
        _: busbar_contract::abi::mechanism::ticket::Ticket,
        _: u64,
        _: &std::task::Waker,
    ) -> std::task::Poll<busbar_contract::io_host::IoResult<(u64, String)>> {
        std::task::Poll::Ready(Err(busbar_contract::io_host::IoRefusal::unknown()))
    }
    fn read(
        &self,
        _: u64,
        _: u64,
        _: &mut [u8],
        _: &std::task::Waker,
    ) -> std::task::Poll<busbar_contract::io_host::IoResult<usize>> {
        std::task::Poll::Ready(Err(busbar_contract::io_host::IoRefusal::unknown()))
    }
    fn write(
        &self,
        _: u64,
        _: u64,
        _: &[u8],
        _: &std::task::Waker,
    ) -> std::task::Poll<busbar_contract::io_host::IoResult<usize>> {
        std::task::Poll::Ready(Err(busbar_contract::io_host::IoRefusal::unknown()))
    }
    fn ready(
        &self,
        _: u64,
        _: u64,
        _: u32,
        _: &std::task::Waker,
    ) -> std::task::Poll<busbar_contract::io_host::IoResult<()>> {
        std::task::Poll::Ready(Err(busbar_contract::io_host::IoRefusal::unknown()))
    }
    fn shut(&self, _: u64, _: u64, _: u32) -> busbar_contract::io_host::IoResult<()> {
        Err(busbar_contract::io_host::IoRefusal::unknown())
    }
    fn close(&self, _: u64, _: u64) -> busbar_contract::io_host::IoResult<()> {
        Err(busbar_contract::io_host::IoRefusal::unknown())
    }
    fn spawn(
        &self,
        _: u64,
        _: busbar_contract::abi::mechanism::ticket::Ticket,
        _: &busbar_contract::io_host::Spawn<'_>,
    ) -> busbar_contract::io_host::IoResult<u64> {
        Err(busbar_contract::io_host::IoRefusal::unknown())
    }
    fn ends(
        &self,
        _: u64,
        _: u64,
    ) -> busbar_contract::io_host::IoResult<busbar_contract::io_host::Ends> {
        Err(busbar_contract::io_host::IoRefusal::unknown())
    }
    fn reap(&self, owner: u64) {
        self.0.lock().unwrap().push(owner);
    }
}

#[test]
fn an_instance_let_go_has_its_io_handles_reaped() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let io = Arc::new(Reaps::default());
    assert!(dispatcher.install_io(io.clone()));
    let row = LinkedRow::of(SCRAPE_DOOR).expect("the door states itself");
    let bind = Bind {
        instance: Arc::from("export.metrics"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: crate::dispatch::ConnTable::Host(crate::actual_exports::prometheus_inbound::table()),
    };
    let plugin = load_linked::<Export>(&row, bind).expect("the linked door loads");
    let owner = plugin.inner.ctx().handle;
    assert!(io.0.lock().unwrap().is_empty());
    drop(plugin);
    assert_eq!(*io.0.lock().unwrap(), vec![owner]);
}

extern "C" fn span_records_door() -> &'static busbar_contract::abi::mechanism::door::Door {
    use busbar_contract::abi::mechanism::door::{Door, Statement};
    use busbar_contract::abi::mechanism::extensions::{encode, statement_blob};
    use std::sync::atomic::{AtomicPtr, Ordering};
    static DOOR: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
    let mut door = DOOR.load(Ordering::Acquire);
    if door.is_null() {
        let real: &'static Door = SCRAPE_DOOR();
        // SAFETY: the real door's Statement is `'static` plugin data.
        let st = unsafe { *real.statement() };
        // SAFETY: as above; its extensions blob holds its stated length.
        let mut ext = unsafe { crate::dispatch::plugin::blob_bytes(st.extensions) }.to_vec();
        ext.extend(encode(&[("span_records", b"true")]));
        let ext: &'static [u8] = Box::leak(ext.into_boxed_slice());
        let stated: &'static Statement = Box::leak(Box::new(Statement {
            extensions: statement_blob(ext),
            ..st
        }));
        let mut d = real.parts();
        d.statement = stated;
        // SAFETY: a copy of the real door with its Statement replaced by a `'static` one.
        let made: *mut Door = Box::leak(Box::new(unsafe { Door::__from_parts(d) }));
        door = match DOOR.compare_exchange(
            std::ptr::null_mut(),
            made,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => made,
            Err(first) => first,
        };
    }
    // SAFETY: a leaked, never-freed `Door`, so `'static`.
    unsafe { &*door }
}

#[test]
fn a_door_that_states_span_records_takes_them() {
    let open = |door: busbar_contract::abi::mechanism::door::DoorFn| {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let row = LinkedRow::of(door).expect("the door states itself");
        let bind = Bind {
            instance: Arc::from("export.metrics"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: crate::dispatch::ConnTable::Host(
                crate::actual_exports::prometheus_inbound::table(),
            ),
        };
        let plugin = load_linked::<Export>(&row, bind).expect("the linked door loads");
        ExportInstance::open(plugin, dispatcher, br#"{"buffer_seconds":60}"#)
            .expect("the sink opens")
    };
    assert!(open(span_records_door).takes_span_records());
    assert!(!open(SCRAPE_DOOR).takes_span_records());
}

mod leaky {
    use busbar_contract::abi::export::{
        CheckIn, CheckOut, DeliverIn, ExportStream, ScrapeIn, ScrapeOut, ServeIn, ServeOut,
        StatusOut, Tail,
    };
    use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};

    pub struct Leaky;

    impl Life for Leaky {
        const CANCEL: u32 = 0;
        fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
            Ok(Leaky)
        }
        fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
            Ok(Refreshed::default())
        }
    }

    pub struct Ready<I, O>(std::marker::PhantomData<(I, O)>);
    impl<I: busbar_contract::abi::sdk::door::AbiIn, O: busbar_contract::abi::sdk::door::AbiOut>
        SafeSlot for Ready<I, O>
    {
        type In = I;
        type Out = O;
        type State = Held<Leaky>;
        fn call(_: Instance<'_, Held<Leaky>>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
            Outcome::Ready
        }
    }

    pub struct Status;
    impl SafeSlot for Status {
        type In = InHead;
        type Out = StatusOut;
        type State = Held<Leaky>;
        fn call(
            i: Instance<'_, Held<Leaky>>,
            _: Lent<'_, InHead>,
            mut out: Out<'_, StatusOut>,
        ) -> Outcome {
            let Some(h) = i.get() else {
                return Outcome::Fault;
            };
            out.keep(h.leases(), vec![0_u8; 64]);
            out.fail(Refusal::failed("the status is unavailable"))
        }
    }

    pub struct Check;
    impl SafeSlot for Check {
        type In = CheckIn;
        type Out = CheckOut;
        type State = Held<Leaky>;
        fn call(
            i: Instance<'_, Held<Leaky>>,
            _: Lent<'_, CheckIn>,
            mut out: Out<'_, CheckOut>,
        ) -> Outcome {
            let Some(h) = i.get() else {
                return Outcome::Fault;
            };
            out.keep(h.leases(), vec![0_u8; 64]);
            out.fail(Refusal::refused("no checks here"))
        }
    }

    pub struct Serve;
    impl SafeSlot for Serve {
        type In = ServeIn;
        type Out = ServeOut;
        type State = Held<Leaky>;
        fn call(
            i: Instance<'_, Held<Leaky>>,
            _: Lent<'_, ServeIn>,
            mut out: Out<'_, ServeOut>,
        ) -> Outcome {
            let held = i.get().map_or(u16::MAX, |h| h.leases().held() as u16);
            out.set(|o| &o.status_code, held);
            Outcome::Ready
        }
    }

    const STREAMS: &[u8] = &[ExportStream::Logs as u8];
    const TAIL: Tail = Tail {
        head: KindTailHead {
            size: std::mem::size_of::<Tail>() as u32,
            ..KindTailHead::ZERO
        },
        streams: STREAMS.as_ptr(),
        streams_len: STREAMS.len(),
        ..Tail::ZERO
    };
    const STATEMENT: Statement = Statement {
        kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
        ..busbar_contract::abi::sdk::door::statement("leaky-export-witness", "0", 4)
    };

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: STATEMENT,
        lifecycle: life(Leaky),
        kind_ops: {
            deliver: Safe<Ready<DeliverIn, OutHead>>,
            scrape: Safe<Ready<ScrapeIn, ScrapeOut>>,
            status: Safe<Status>,
            check: Safe<Check>,
            serve: Safe<Serve>,
        },
    }
}

#[test]
fn a_lease_named_on_a_failed_or_refused_answer_is_released() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(leaky::door).expect("the door states itself");
    let bind = Bind {
        instance: Arc::from("export.leaky"),
        max_inflight_cap: 4,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    };
    let plugin = load_linked::<Export>(&row, bind).expect("the linked door loads");
    let sink = ExportInstance::open(plugin, dispatcher, b"{}").expect("the witness opens");
    assert_eq!(sink.status(), None, "a FAILED status reports nothing");
    assert!(
        check(sink.plugin(), 0, &[]).is_err(),
        "a REFUSED check is an error"
    );
    let req = ServeRequest {
        method: "GET",
        path: "/exports/leaky/held",
        query: None,
        headers: &[],
        body: &[],
    };
    let held = sink.serve(&req).expect("serve answers").status;
    assert_eq!(
        held, 0,
        "leases the plugin still holds after FAILED/REFUSED answers"
    );
}

mod push_only {
    use busbar_contract::abi::export::{
        CheckIn, CheckOut, DeliverIn, ExportStream, Route, StatusOut, Tail, ROUTE_AUTH_KEY,
    };
    use busbar_contract::abi::mechanism::call::{AbiStr, InHead, OutHead};
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::sdk::Safe;

    use super::leaky::Ready;

    const STREAMS: &[u8] = &[ExportStream::Logs as u8];
    const TAIL: Tail = Tail {
        head: KindTailHead {
            size: std::mem::size_of::<Tail>() as u32,
            ..KindTailHead::ZERO
        },
        streams: STREAMS.as_ptr(),
        streams_len: STREAMS.len(),
        ..Tail::ZERO
    };
    const STATEMENT: Statement = Statement {
        kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
        ..busbar_contract::abi::sdk::door::statement("push-only-export-witness", "0", 4)
    };

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: STATEMENT,
        lifecycle: life(super::leaky::Leaky),
        kind_ops: {
            deliver: Safe<Ready<DeliverIn, OutHead>>,
            status: Safe<Ready<InHead, StatusOut>>,
            check: Safe<Ready<CheckIn, CheckOut>>,
        },
    }

    pub mod routed {
        use super::*;

        const PATH: &str = "/exports/routed/state";
        const ROUTES: &[Route] = &[Route {
            path: AbiStr {
                ptr: PATH.as_ptr(),
                len: PATH.len(),
            },
            method: AbiStr {
                ptr: "GET".as_ptr(),
                len: 3,
            },
            auth: ROUTE_AUTH_KEY,
            _reserved: 0,
        }];
        const TAIL: Tail = Tail {
            routes: ROUTES.as_ptr(),
            routes_len: ROUTES.len(),
            ..super::TAIL
        };
        const STATEMENT: Statement = Statement {
            kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
            ..busbar_contract::abi::sdk::door::statement("routed-export-witness", "0", 4)
        };

        busbar_contract::plugin_door! {
            ops: busbar_contract::abi::export::Ops,
            statement: STATEMENT,
            lifecycle: life(super::super::leaky::Leaky),
            kind_ops: {
                deliver: Safe<Ready<DeliverIn, OutHead>>,
                status: Safe<Ready<InHead, StatusOut>>,
                check: Safe<Ready<CheckIn, CheckOut>>,
            },
        }
    }
}

#[test]
fn a_push_sink_may_leave_scrape_and_serve_unstated() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = |name: &str| Bind {
        instance: Arc::from(name),
        max_inflight_cap: 4,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    };
    let row = LinkedRow::of(push_only::door).expect("the door states itself");
    let plugin = load_linked::<Export>(&row, bind("export.push")).expect("the push sink loads");
    ExportInstance::open(plugin, dispatcher.clone(), b"{}").expect("the push sink opens");
    let routed = LinkedRow::of(push_only::routed::door).expect("the door states itself");
    let Err(refused) = load_linked::<Export>(&routed, bind("export.routed")) else {
        panic!("a door that declares a route owes serve");
    };
    assert_eq!(
        refused.to_string(),
        crate::dispatch::LoadError::NullSlot(slot::SERVE).to_string()
    );
}
