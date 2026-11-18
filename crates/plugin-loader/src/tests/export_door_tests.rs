// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, OnceLock};

use busbar_contract::export_calls::ServeRequest;
use busbar_contract::export_stream::ExportStream;

use super::*;
use crate::dispatch::{load_linked, Bind, DispatchConfig, LinkedRow, NoSink};

pub(crate) const TEST_EXPORT_DOOR: busbar_contract::abi::mechanism::door::DoorFn = metadata_door;

// This synthetic kind declaration exercises host metadata/lifetime handling. It
// has no concrete exporter grammar, destination, or product image dependency.
extern "C" fn metadata_door() -> &'static busbar_contract::abi::mechanism::door::Door {
    use busbar_contract::abi::export::{Route, ROUTE_AUTH_KEY};
    use busbar_contract::abi::mechanism::door::{Door, KindTailHead};
    use busbar_contract::abi::sdk::door::abi_str;
    const ROUTES: &[Route] = &[
        Route {
            path: abi_str("/capture"),
            method: abi_str("GET"),
            auth: ROUTE_AUTH_KEY,
            _reserved: 0,
        },
        Route {
            path: abi_str("/retained"),
            method: abi_str("GET"),
            auth: ROUTE_AUTH_KEY,
            _reserved: 0,
        },
    ];
    const TAIL: busbar_contract::abi::export::Tail =
        busbar_contract::abi::sdk::export::tail(&[ExportStream::Logs as u8], ROUTES);
    busbar_contract::statement_extensions!(EXTENSIONS: [
        (busbar_contract::export_calls::EXT_PUBLIC_ROUTES, br#"["/capture","/retained"]"#),
        (busbar_contract::export_calls::EXT_PERSISTENT_ROUTES, br#"["/retained"]"#),
    ]);
    static DOOR: OnceLock<std::sync::atomic::AtomicPtr<Door>> = OnceLock::new();
    let door = DOOR
        .get_or_init(|| {
            let base = leaky::door();
            // SAFETY: the synthetic SDK declaration is immutable process-lived data.
            let mut statement = unsafe { *base.statement() };
            statement.name = abi_str("metadata-export-witness");
            statement.kind_tail =
                (&TAIL as *const busbar_contract::abi::export::Tail).cast::<KindTailHead>();
            statement.extensions = EXTENSIONS;
            let statement = Box::leak(Box::new(statement));
            let mut parts = base.parts();
            parts.statement = statement;
            // SAFETY: metadata remains process-lived; the complete typed SDK table is unchanged.
            std::sync::atomic::AtomicPtr::new(Box::into_raw(Box::new(unsafe {
                Door::__from_parts(parts)
            })))
        })
        .load(Ordering::Acquire);
    // SAFETY: OnceLock publishes this one immutable allocation, retained for the process.
    unsafe { &*door }
}

fn linked() -> (Plugin<Export>, Arc<Dispatcher>) {
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let row = LinkedRow::of(TEST_EXPORT_DOOR).expect("the door states itself");
    let bind = Bind {
        accept: Default::default(),
        instance: Arc::from("export.metrics"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    };
    let plugin = load_linked::<Export>(&row, bind).expect("the linked door loads");
    (plugin, dispatcher)
}

#[test]
fn the_tail_is_read_at_bind() {
    let (plugin, _) = linked();
    let facts = plugin.context::<ExportFacts>().expect("an export tail");
    assert_eq!(facts.streams, vec![ExportStream::Logs as u8]);
    let routes: Vec<String> = facts
        .routes
        .iter()
        .map(|r| format!("{} {} {:?}", r.method.as_str(), r.path, r.auth))
        .collect();
    assert_eq!(
        routes,
        ["GET /capture Key", "GET /retained Key"],
        "the kind declaration carries both synthetic routes"
    );
}

#[test]
fn listener_policy_is_copied_from_the_statement_into_the_opened_sink() {
    let (plugin, dispatcher) = linked();
    let facts = plugin.context::<ExportFacts>().unwrap();
    assert_eq!(facts.public_routes, ["/capture", "/retained"]);
    assert_eq!(facts.persistent_routes, ["/retained"]);
    let sink = ExportInstance::open(plugin, dispatcher, b"{}").unwrap();
    assert_eq!(sink.public_routes(), ["/capture", "/retained"]);
    assert_eq!(sink.persistent_routes(), ["/retained"]);
}

#[test]
fn listener_policy_rejects_undeclared_and_non_public_persistent_paths() {
    use busbar_contract::abi::mechanism::extensions::{encode, statement_blob};
    let context = |public: &[u8], persistent: &[u8]| {
        let bytes = Box::leak(
            encode(&[
                ("listener.public_routes", public),
                ("listener.persistent_routes", persistent),
            ])
            .into_boxed_slice(),
        );
        // SAFETY: the fixture door's Statement lives for the process.
        let mut statement = unsafe { *TEST_EXPORT_DOOR().statement() };
        statement.extensions = statement_blob(bytes);
        <Export as crate::dispatch::Kind>::context(&statement)
    };
    // Positive control: the same construction with declared, consistent paths is accepted.
    assert!(
        context(br#"["/capture"]"#, br#"[]"#).is_ok(),
        "a declared public route must be accepted"
    );
    for (public, persistent) in [
        (br#"["/not-declared"]"#.as_slice(), br#"[]"#.as_slice()),
        (br#"[]"#.as_slice(), br#"["/retained"]"#.as_slice()),
    ] {
        let err = context(public, persistent).expect_err("refused");
        assert!(err.contains("listener route policy"), "{err}");
    }
    for (public, persistent) in [
        (
            br#"["/capture","/capture"]"#.as_slice(),
            br#"[]"#.as_slice(),
        ),
        (br#"false"#.as_slice(), br#"[]"#.as_slice()),
    ] {
        assert!(context(public, persistent).is_err());
    }
}

#[test]
fn a_dropped_instance_is_closed() {
    let (plugin, dispatcher) = linked();
    let sink = ExportInstance::open(plugin, dispatcher, b"{}").expect("the sink opens");
    let instance = Arc::clone(&sink.plugin().inner);
    assert!(instance.is_open());
    drop(sink);
    assert!(!instance.is_open(), "the dropped instance was never closed");
}

extern "C" fn stop_accounting_door() -> &'static busbar_contract::abi::mechanism::door::Door {
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    let door = TEST_EXPORT_DOOR();
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
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let plugin = load_linked::<Export>(
        &LinkedRow::of(stop_accounting_door).unwrap(),
        Bind {
            accept: Default::default(),
            instance: Arc::from("export.stop-accounting"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .unwrap();
    let opened = plugin.call(lc::OPEN, &mut open_frame(blob(b"{}", BLOB_JSON)));
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
        recorder: None,
        facts: plugin.context::<ExportFacts>().unwrap().clone(),
        plugin,
        dispatcher,
        queue: Mutex::default(),
        shed_pending: AtomicU64::new(0),
        flusher: Mutex::default(),
        stop: AtomicBool::new(false),
        abandon: AtomicBool::new(false),
        node: crate::cold::export_door::node_id(),
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
                ExportStream::Logs as u8,
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
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let io = Arc::new(Reaps::default());
    assert!(dispatcher.install_io(io.clone()));
    let row = LinkedRow::of(TEST_EXPORT_DOOR).expect("the door states itself");
    let bind = Bind {
        accept: Default::default(),
        instance: Arc::from("export.metrics"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
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
        let real: &'static Door = TEST_EXPORT_DOOR();
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
        let dispatcher = Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        ));
        let row = LinkedRow::of(door).expect("the door states itself");
        let bind = Bind {
            accept: Default::default(),
            instance: Arc::from("export.metrics"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        };
        let plugin = load_linked::<Export>(&row, bind).expect("the linked door loads");
        ExportInstance::open(plugin, dispatcher, b"{}").expect("the sink opens")
    };
    assert!(open(span_records_door).takes_span_records());
    assert!(!open(TEST_EXPORT_DOOR).takes_span_records());
}

mod leaky {
    use busbar_contract::abi::export::{
        CheckIn, CheckOut, DeliverIn, ScrapeIn, ScrapeOut, ServeIn, ServeOut, StatusOut, Tail,
    };
    use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
    use busbar_contract::export_stream::ExportStream;

    pub struct Leaky;

    impl Life for Leaky {
        type Kind = busbar_contract::plugin::markers::ExportKind;
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
        type Kind = busbar_contract::plugin::markers::ExportKind;
        type In = I;
        type Out = O;
        type State = Held<Leaky>;
        fn call(
            _: Instance<'_, Held<Leaky>, Self::Kind>,
            _: Lent<'_, I>,
            _: Out<'_, O>,
        ) -> Outcome {
            Outcome::Ready
        }
    }

    pub struct Status;
    impl SafeSlot for Status {
        type Kind = busbar_contract::plugin::markers::ExportKind;
        type In = InHead;
        type Out = StatusOut;
        type State = Held<Leaky>;
        fn call(
            i: Instance<'_, Held<Leaky>, Self::Kind>,
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
        type Kind = busbar_contract::plugin::markers::ExportKind;
        type In = CheckIn;
        type Out = CheckOut;
        type State = Held<Leaky>;
        fn call(
            i: Instance<'_, Held<Leaky>, Self::Kind>,
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
        type Kind = busbar_contract::plugin::markers::ExportKind;
        type In = ServeIn;
        type Out = ServeOut;
        type State = Held<Leaky>;
        fn call(
            i: Instance<'_, Held<Leaky>, Self::Kind>,
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
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let row = LinkedRow::of(leaky::door).expect("the door states itself");
    let bind = Bind {
        accept: Default::default(),
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
        CheckIn, CheckOut, DeliverIn, Route, StatusOut, Tail, ROUTE_AUTH_KEY,
    };
    use busbar_contract::abi::mechanism::call::{AbiStr, InHead, OutHead};
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::sdk::Safe;
    use busbar_contract::export_stream::ExportStream;

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

        pub extern "C" fn door() -> &'static busbar_contract::abi::mechanism::door::Door {
            use busbar_contract::abi::mechanism::door::{Door, DoorParts};
            const STAMPED: Statement = busbar_contract::abi::sdk::door::stamp::<
                busbar_contract::abi::export::Ops,
            >(STATEMENT);
            // SAFETY: the valid push-only table and this declaration are immutable,
            // process-lived data. Deliberately adding a route without SERVE models a
            // malformed foreign ABI descriptor, which the host must reject.
            Box::leak(Box::new(unsafe {
                Door::__from_parts(DoorParts {
                    statement: &STAMPED,
                    ..super::door().parts()
                })
            }))
        }
    }
}

#[test]
fn a_push_sink_may_leave_scrape_and_serve_unstated() {
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let bind = |name: &str| Bind {
        accept: Default::default(),
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

mod pl_src_1_failing {
    use busbar_contract::abi::export::{
        CheckIn, CheckOut, DeliverIn, ScrapeIn, ScrapeOut, ServeIn, ServeOut, StatusOut, Tail,
    };
    use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
    use busbar_contract::export_stream::ExportStream;

    use super::leaky::{Leaky, Ready};
    use busbar_contract::abi::sdk::life::Held;

    pub struct Fails;
    impl SafeSlot for Fails {
        type Kind = busbar_contract::plugin::markers::ExportKind;
        type In = DeliverIn;
        type Out = OutHead;
        type State = Held<Leaky>;
        fn call(
            _: Instance<'_, Held<Leaky>, Self::Kind>,
            _: Lent<'_, DeliverIn>,
            _: Out<'_, OutHead>,
        ) -> Outcome {
            Outcome::Failed
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
        ..busbar_contract::abi::sdk::door::statement("pl-src-1-failing-export", "0", 4)
    };

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: STATEMENT,
        lifecycle: life(Leaky),
        kind_ops: {
            deliver: Safe<Fails>,
            scrape: Safe<Ready<ScrapeIn, ScrapeOut>>,
            status: Safe<Ready<InHead, StatusOut>>,
            check: Safe<Ready<CheckIn, CheckOut>>,
            serve: Safe<Ready<ServeIn, ServeOut>>,
        },
    }
}

#[test]
fn a_batch_dropped_after_failed_delivery_is_counted_as_shed() {
    let guard = crate::observe::testing::exclusive();
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let plugin = load_linked::<Export>(
        &LinkedRow::of(pl_src_1_failing::door).unwrap(),
        Bind {
            accept: Default::default(),
            instance: Arc::from("export.pl-src-1-failing"),
            max_inflight_cap: 4,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .unwrap();
    let opened = plugin.call(lc::OPEN, &mut open_frame(blob(b"{}", BLOB_JSON)));
    assert_eq!(opened.outcome, Outcome::Ready);
    let mut series = busbar_contract::abi::mechanism::observe::SeriesDecl::new(
        "busbar_export_pl_src_1_failing_shed",
        "counter",
    );
    series.shed = true;
    let _grant =
        crate::observe::grant_series(dispatcher.observing(), plugin.name(), true, &[series])
            .unwrap();
    let shared = Arc::new(Shared {
        facts: plugin.context::<ExportFacts>().unwrap().clone(),
        recorder: None,
        plugin,
        dispatcher,
        queue: Mutex::default(),
        shed_pending: AtomicU64::new(0),
        flusher: Mutex::default(),
        stop: AtomicBool::new(false),
        abandon: AtomicBool::new(false),
        node: crate::cold::export_door::node_id(),
        minted: AtomicU64::new(0),
    });
    crate::observe::testing::clear(&guard);
    let lines = (0..3)
        .map(|i| Line {
            stream: ExportStream::Logs as u8,
            bytes: busbar_contract::secure::SecureVec::from(
                format!("{{\"line\":{i}}}").into_bytes(),
            ),
            _hold: Box::new(()),
        })
        .collect();
    futures::executor::block_on(Arc::clone(&shared).deliver(0, ExportStream::Logs as u8, lines));
    let shed: u64 = crate::observe::testing::folds()
        .iter()
        .flat_map(|(_, _, metrics, _)| metrics)
        .filter(|metric| metric["name"] == "busbar_export_pl_src_1_failing_shed")
        .map(|metric| metric["value"].as_u64().unwrap())
        .sum();
    assert_eq!(shed, 3, "every line lost to a failed delivery is counted");
    let mut close = Frame::new(in_head(), out_head());
    let _ = shared.plugin.call(lc::CLOSE, &mut close);
}

/// A DELIVER that answers READY and counts each batch and its lines.
mod counting {
    use busbar_contract::abi::export::{
        CheckIn, CheckOut, DeliverIn, ScrapeIn, ScrapeOut, ServeIn, ServeOut, StatusOut, Tail,
    };
    use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
    use busbar_contract::export_stream::ExportStream;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::leaky::{Leaky, Ready};
    use busbar_contract::abi::sdk::life::Held;

    pub static DELIVERS: AtomicUsize = AtomicUsize::new(0);
    pub static LINES: AtomicUsize = AtomicUsize::new(0);

    pub struct Counts;
    impl SafeSlot for Counts {
        type Kind = busbar_contract::plugin::markers::ExportKind;
        type In = DeliverIn;
        type Out = OutHead;
        type State = Held<Leaky>;
        fn call(
            _: Instance<'_, Held<Leaky>, Self::Kind>,
            input: Lent<'_, DeliverIn>,
            _: Out<'_, OutHead>,
        ) -> Outcome {
            let lines = input
                .batch()
                .bytes()
                .iter()
                .filter(|b| **b == b'\n')
                .count();
            DELIVERS.fetch_add(1, Ordering::SeqCst);
            LINES.fetch_add(lines, Ordering::SeqCst);
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
        ..busbar_contract::abi::sdk::door::statement("waste-counting-export", "0", 4)
    };

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: STATEMENT,
        lifecycle: life(Leaky),
        kind_ops: {
            deliver: Safe<Counts>,
            scrape: Safe<Ready<ScrapeIn, ScrapeOut>>,
            status: Safe<Ready<InHead, StatusOut>>,
            check: Safe<Ready<CheckIn, CheckOut>>,
            serve: Safe<Ready<ServeIn, ServeOut>>,
        },
    }

    /// The counting DELIVER with 64 deliveries in flight, stating no carriage
    /// fact: core treats it as carrying a batch line by line.
    pub mod per_line {
        use super::*;

        const STATEMENT: Statement = Statement {
            kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
            ..busbar_contract::abi::sdk::door::statement("waste-per-line-export", "0", 64)
        };

        busbar_contract::plugin_door! {
            ops: busbar_contract::abi::export::Ops,
            statement: STATEMENT,
            lifecycle: life(Leaky),
            kind_ops: {
                deliver: Safe<Counts>,
                scrape: Safe<Ready<ScrapeIn, ScrapeOut>>,
                status: Safe<Ready<InHead, StatusOut>>,
                check: Safe<Ready<CheckIn, CheckOut>>,
                serve: Safe<Ready<ServeIn, ServeOut>>,
            },
        }
    }

    /// The counting DELIVER with 64 deliveries in flight, stating
    /// `whole_batches`: it carries a DELIVER as one unit.
    pub mod whole {
        use super::*;

        busbar_contract::statement_extensions!(EXTENSIONS: [("whole_batches", b"true")]);
        const STATEMENT: Statement = Statement {
            kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
            extensions: EXTENSIONS,
            ..busbar_contract::abi::sdk::door::statement("waste-whole-export", "0", 64)
        };

        busbar_contract::plugin_door! {
            ops: busbar_contract::abi::export::Ops,
            statement: STATEMENT,
            lifecycle: life(Leaky),
            kind_ops: {
                deliver: Safe<Counts>,
                scrape: Safe<Ready<ScrapeIn, ScrapeOut>>,
                status: Safe<Ready<InHead, StatusOut>>,
                check: Safe<Ready<CheckIn, CheckOut>>,
                serve: Safe<Ready<ServeIn, ServeOut>>,
            },
        }
    }
}

const COUNTING_SHED: &str = "busbar_export_waste_counting_shed";

/// An opened counting sink with no flusher running yet, so a test can queue
/// lines first and then run the flusher itself.
fn counting_sink() -> (ExportInstance, Arc<Shared>) {
    counting_sink_of(counting::door)
}

/// [`counting_sink`] over `door`, one of the counting doors.
fn counting_sink_of(
    door: busbar_contract::abi::mechanism::door::DoorFn,
) -> (ExportInstance, Arc<Shared>) {
    use std::sync::atomic::Ordering::SeqCst;
    counting::DELIVERS.store(0, SeqCst);
    counting::LINES.store(0, SeqCst);
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let plugin = load_linked::<Export>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            accept: Default::default(),
            instance: Arc::from("export.waste-counting"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .unwrap();
    let opened = plugin.call(lc::OPEN, &mut open_frame(blob(b"{}", BLOB_JSON)));
    assert_eq!(opened.outcome, Outcome::Ready);
    let mut series =
        busbar_contract::abi::mechanism::observe::SeriesDecl::new(COUNTING_SHED, "counter");
    series.shed = true;
    let grant =
        crate::observe::grant_series(dispatcher.observing(), plugin.name(), true, &[series])
            .unwrap();
    let shared = Arc::new(Shared {
        facts: plugin.context::<ExportFacts>().unwrap().clone(),
        recorder: None,
        plugin,
        dispatcher,
        queue: Mutex::default(),
        shed_pending: AtomicU64::new(0),
        flusher: Mutex::default(),
        stop: AtomicBool::new(false),
        abandon: AtomicBool::new(false),
        node: crate::cold::export_door::node_id(),
        minted: AtomicU64::new(0),
    });
    let sink = ExportInstance {
        shared: Arc::clone(&shared),
        flusher: Mutex::new(None),
        _grant: Some(grant),
    };
    (sink, shared)
}

fn queue_lines(sink: &ExportInstance, count: usize) {
    for i in 0..count {
        assert_eq!(
            sink.deliver(
                ExportStream::Logs as u8,
                format!("{{\"line\":{i}}}").into_bytes(),
                Box::new(())
            ),
            Delivered::Queued
        );
    }
}

/// Runs the flusher until `lines` lines were delivered (or 10 s), then stops it.
/// The flusher thread carries this test's observe scope, so what it folds is
/// read back under the test's `exclusive` guard.
fn flush_until(shared: &Arc<Shared>, lines: usize) {
    let scope = crate::observe::testing::scope();
    let flusher = std::thread::spawn({
        let shared = Arc::clone(shared);
        move || {
            crate::observe::testing::enter(scope);
            shared.flush();
        }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while counting::LINES.load(Ordering::SeqCst) < lines && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    shared.stop.store(true, Ordering::Release);
    shared.notify();
    flusher.join().unwrap();
}

fn counting_shed_folds() -> Vec<u64> {
    crate::observe::testing::folds()
        .iter()
        .flat_map(|(_, _, metrics, _)| metrics)
        .filter(|metric| metric["name"] == COUNTING_SHED)
        .map(|metric| metric["value"].as_u64().unwrap())
        .collect()
}

#[test]
fn shed_folds_once_per_pass() {
    let guard = crate::observe::testing::exclusive();
    let (sink, shared) = counting_sink();
    crate::observe::testing::clear(&guard);
    for _ in 0..1000 {
        sink.shed(busbar_contract::export_calls::ExportLossKind::CaptureRefused);
    }
    flush_until(&shared, 0);
    let folds = counting_shed_folds();
    assert_eq!(
        folds.iter().sum::<u64>(),
        1000,
        "every shed line is counted"
    );
    assert!(
        folds.len() <= 2,
        "1000 sheds are folded in {} observer folds",
        folds.len()
    );
}

/// Queues `count` lines on a fresh counting sink over `door`, runs the flusher
/// until all are delivered, and returns (DELIVERs, lines delivered).
fn delivers_for(
    door: busbar_contract::abi::mechanism::door::DoorFn,
    count: usize,
) -> (usize, usize) {
    let (sink, shared) = counting_sink_of(door);
    queue_lines(&sink, count);
    flush_until(&shared, count);
    drop(sink);
    (
        counting::DELIVERS.load(Ordering::SeqCst),
        counting::LINES.load(Ordering::SeqCst),
    )
}

#[test]
fn export_batches_low_load() {
    let guard = crate::observe::testing::exclusive();
    crate::observe::testing::clear(&guard);
    assert_eq!(
        delivers_for(counting::whole::door, 50),
        (1, 50),
        "a whole-batch carrier takes 50 queued lines as one DELIVER, not one per free slot"
    );
    assert!(counting_shed_folds().is_empty());
}

#[test]
fn export_batches_are_full_under_load() {
    let guard = crate::observe::testing::exclusive();
    crate::observe::testing::clear(&guard);
    assert_eq!(
        delivers_for(counting::whole::door, 1000),
        (1000usize.div_ceil(MAX_BATCH_LINES), 1000),
        "a whole-batch carrier takes 1000 queued lines in full batches"
    );
    assert!(counting_shed_folds().is_empty());
}

#[test]
fn per_line_carriers_keep_dev_cut() {
    let guard = crate::observe::testing::exclusive();
    crate::observe::testing::clear(&guard);
    // dev's cut with 64 free slots: `ceil(queued / room)` lines per DELIVER,
    // room counting down from 64, so every free slot carries its share.
    assert_eq!(delivers_for(counting::per_line::door, 50), (50, 50));
    assert_eq!(delivers_for(counting::per_line::door, 1000), (64, 1000));
    assert!(counting_shed_folds().is_empty());
}

/// Counts how often the flusher's waker is woken.
struct CountWakes(std::sync::atomic::AtomicUsize);
impl std::task::Wake for CountWakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn a_busy_flusher_is_not_woken_by_pushes_into_a_non_empty_queue() {
    let guard = crate::observe::testing::exclusive();
    crate::observe::testing::clear(&guard);
    let (sink, shared) = counting_sink();
    let wakes = Arc::new(CountWakes(std::sync::atomic::AtomicUsize::new(0)));
    let waker = std::task::Waker::from(Arc::clone(&wakes));
    *shared.flusher.lock().unwrap() = Some(waker.clone());
    queue_lines(&sink, 1);
    assert_eq!(
        wakes.0.load(Ordering::SeqCst),
        1,
        "the first line into an empty queue wakes the flusher"
    );
    // The flusher stores its waker again each pass and leaves lines queued only
    // when every slot is busy; a deliver completion wakes it then, not a push.
    *shared.flusher.lock().unwrap() = Some(waker);
    queue_lines(&sink, 999);
    assert_eq!(
        wakes.0.load(Ordering::SeqCst),
        1,
        "pushes into a non-empty queue do not wake the flusher"
    );
    assert!(shared.flusher.lock().unwrap().is_some());
    assert_eq!(sink.queued(), 1000);
}

/// The arrays a scrape lends: every family, sample and label, in order, each lent from its source
/// text; a sample's labels and a family's samples are its own stretch of the one run; an empty
/// list is lent as null with a count of zero; laying out again reuses the same three arrays.
#[test]
fn a_scrape_lends_every_family_sample_and_label_in_order_from_one_run_each() {
    use busbar_contract::export_calls::{Family, Sample};
    let sample = |name: &str, labels: &[(&str, &str)], value: &str| Sample {
        name: name.into(),
        labels: labels
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        value: value.into(),
    };
    let family = |name: &str, help: Option<&str>, unit: Option<&str>, kind: u8, samples| Family {
        name: name.into(),
        help: help.map(Into::into),
        unit: unit.map(Into::into),
        kind,
        samples,
    };
    let families = vec![
        family(
            "requests",
            Some("served"),
            None,
            1,
            vec![
                sample("requests", &[("lane", "a"), ("code", "200")], "7"),
                sample("requests", &[], "9"),
            ],
        ),
        family("idle", None, Some("seconds"), 2, Vec::new()),
        family(
            "latency",
            None,
            None,
            3,
            vec![
                sample("latency_bucket", &[("le", "0.5")], "3"),
                sample(
                    "latency_sum",
                    &[("lane", "a"), ("x", "y"), ("z", "")],
                    "1.5",
                ),
                sample("latency_count", &[], "3"),
            ],
        ),
    ];
    let lent = |a: AbiStr, s: &str| (a.ptr, a.len) == (s.as_ptr(), s.len());
    let mut lowered = Lowered::default();
    for pass in 0..2 {
        lower(&mut lowered, &families);
        assert_eq!(lowered.families.len(), 3, "pass {pass}");
        assert_eq!(lowered.samples.len(), 5, "pass {pass}");
        assert_eq!(lowered.labels.len(), 6, "pass {pass}");
        let (mut sample_at, mut label_at) = (0usize, 0usize);
        for (f, l) in families.iter().zip(&lowered.families) {
            assert!(lent(l.name, &f.name));
            match &f.help {
                Some(help) => assert!(lent(l.help, help)),
                None => assert!(l.help.ptr.is_null() && l.help.len == 0),
            }
            match &f.unit {
                Some(unit) => assert!(lent(l.unit, unit)),
                None => assert!(l.unit.ptr.is_null() && l.unit.len == 0),
            }
            assert_eq!((l.kind, l._reserved), (f.kind, [0; 7]));
            assert_eq!(l.samples_len, f.samples.len());
            if f.samples.is_empty() {
                assert!(l.samples.is_null(), "an empty sample list is lent as null");
            } else {
                assert_eq!(l.samples, lowered.samples[sample_at..].as_ptr());
            }
            for s in &f.samples {
                let ls = &lowered.samples[sample_at];
                sample_at += 1;
                assert!(lent(ls.name, &s.name) && lent(ls.value, &s.value));
                assert_eq!(ls.labels_len, s.labels.len());
                if s.labels.is_empty() {
                    assert!(ls.labels.is_null(), "an empty label list is lent as null");
                } else {
                    assert_eq!(ls.labels, lowered.labels[label_at..].as_ptr());
                }
                for (k, v) in &s.labels {
                    let ll = &lowered.labels[label_at];
                    label_at += 1;
                    assert!(lent(ll.key, k) && lent(ll.value, v));
                }
            }
        }
        assert_eq!(
            (sample_at, label_at),
            (5, 6),
            "nothing is lent twice or left out"
        );
    }
    lower(&mut lowered, &[]);
    assert!(lowered.families.is_empty() && lowered.samples.is_empty() && lowered.labels.is_empty());
}
