// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`ExportInstance`] on the one dispatcher, over the real prometheus sink LINKED by its door: its
//! Statement tail read at bind, its settings judged before it opens, its scrape rendering the host
//! snapshot, the one re-call a short answer earns, and the ops it does not serve answered as such.

use std::sync::Arc;

use busbar_contract::abi::export::ExportStream;
use busbar_contract::export_calls::{parse_families, ServeRequest};

use super::*;
use crate::dispatch::{load_linked, Bind, DispatchConfig, LinkedRow, NoSink};

/// The real scrape sink's door, LINKED, reached by the both-ways table's `export-scrape` row: the
/// one place the loader's export tests take it (`conformance::export`'s unjudged test restates it).
pub(crate) const SCRAPE_DOOR: busbar_contract::abi::mechanism::door::DoorFn =
    crate::both_ways::export_scrape_fixture::door::door;

fn linked() -> (Plugin<Export>, Arc<Dispatcher>) {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(SCRAPE_DOOR).expect("the door states itself");
    let bind = Bind {
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
    // Larger than the first exposition buffer: the sink answers short, the host grows it once.
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

/// THE HOOK FAMILIES' FLAG RIDES THROUGH THE DISPATCHER (P2 D4): `scrape_hooks` sets
/// `SCRAPE_FLAG_HOOK_FAMILIES` on the head, the dispatcher keeps it (it clears only its own bit), and
/// the sink renders the 1.5.5 `/metrics/hooks` layout — on the short answer's re-call too. RED: a
/// dispatcher that zeroes the head renders the `/metrics` layout (a blank line after each family).
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

/// RED (export ABI defect 4): dropping an opened instance sends its `close`. Before, the export
/// path never closed an instance, so each instance a configuration check opened stayed open.
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

/// RED (transport ABI defect 2): an instance the host lets go has every host I/O handle it still
/// owns released for it (`IoHost::reap`, under the instance's own handle), so a listener or socket
/// it never closed does not outlive it. Before, the host released a handle only when the plugin
/// closed it.
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
        conns: crate::dispatch::ConnTable::NoNeeds,
    };
    let plugin = load_linked::<Export>(&row, bind).expect("the linked door loads");
    let owner = plugin.inner.ctx().handle;
    assert!(io.0.lock().unwrap().is_empty());
    drop(plugin);
    assert_eq!(*io.0.lock().unwrap(), vec![owner]);
}

/// The scrape sink's door with `span_records: true` added to its Statement's extensions.
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

/// A DOOR STATES IT TAKES FULL SPAN RECORDS through its Statement's extensions (`span_records`,
/// status row 173): the instance it opens answers `takes_span_records`, so the kernel adds each
/// `traces` line's `span` member (everything the previous release's exporter sent: attributes,
/// events, status). A door that states nothing takes none. RED: an instance that never answers it
/// leaves every export door's span record unsent.
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
            conns: crate::dispatch::ConnTable::NoNeeds,
        };
        let plugin = load_linked::<Export>(&row, bind).expect("the linked door loads");
        ExportInstance::open(plugin, dispatcher, br#"{"buffer_seconds":60}"#)
            .expect("the sink opens")
    };
    assert!(open(span_records_door).takes_span_records());
    assert!(!open(SCRAPE_DOOR).takes_span_records());
}

/// THE LEAK WITNESS: an export door whose `status` answers FAILED and whose `check` answers REFUSED,
/// each still naming a lease over bytes it holds, and whose `serve` answers READY with how many
/// leases it still holds as its status code.
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

/// RED (export ABI defect 6): a lease an answer names is released whatever the outcome. Before, the
/// host released a lease only on READY, so a FAILED `status` or a REFUSED `check` that named one
/// left the plugin holding its memory for the instance's life.
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

/// A PUSH-ONLY export door: it carries `logs`, declares no route and states no `scrape` and no
/// `serve` (both NULL in its table); `ROUTED` declares a route and still states no `serve`.
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

/// RED (export ABI defect 2): the export kind's own ops a door's Statement makes unreachable are
/// optional — `scrape` with no `metrics` stream, `serve` with no route, `deliver` with no stream
/// but `metrics` — so a push sink states neither `scrape` nor `serve`. A door that declares a route
/// still owes `serve`. Before, every export slot was mandatory and the push sink was refused.
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
