// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINT-RULES R28 `ready-after-no-ticket`: a ticketless call the SDK handed `NoTicket` (it needed to
//! pend and could not) that still answers READY claims a success it never had. The SDK door entry
//! judges it FAULT in debug builds. Toy SDK export doors, linked and driven through
//! `Plugin::call` (always ticketless), pin what is judged and what is not, including door entries
//! that nest on one thread.

use std::cell::RefCell;
use std::sync::Arc;

use busbar_contract::abi::export::{CheckIn, CheckOut, DeliverIn, ExportStream, Tail};
use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, BLOB_JSON, BLOB_JSONL};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::door::{blank_in, blank_out, statement};
use busbar_contract::abi::sdk::export::{tail, NoScrape, NoServe, Quiet};
use busbar_contract::abi::sdk::life::{Held, Life, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::plugin::markers::ExportKind;

use crate::dispatch::kinds::export::Export;
use crate::dispatch::{
    in_head, load_linked, out_head, Bind, Called, ConnTable, DispatchConfig, Dispatcher, Frame,
    LinkedRow, NoSink, Plugin,
};

/// What the toy's `deliver` does, named by its settings.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Ask the connector for a service, then answer READY whatever it said.
    ConnectorThenReady,
    /// Ask the connector for a service and answer REFUSED with what it said.
    ConnectorThenRefused,
    /// No I/O at all: READY (a prometheus-shaped `deliver`).
    Quiet,
    /// Ask the connector (handed `NoTicket`), then make a nested ticketless call to [`INNER`],
    /// then answer READY.
    ConnectorThenNestedThenReady,
    /// No I/O of its own: a nested ticketless call to [`INNER`], then READY.
    NestedThenReady,
}

struct Toy(Mode);

impl Life for Toy {
    type Kind = ExportKind;
    const CANCEL: u32 = 0;
    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self(match settings {
            b"connector-then-ready" => Mode::ConnectorThenReady,
            b"connector-then-refused" => Mode::ConnectorThenRefused,
            b"quiet" => Mode::Quiet,
            b"connector-then-nested-then-ready" => Mode::ConnectorThenNestedThenReady,
            b"nested-then-ready" => Mode::NestedThenReady,
            _ => return Err(Refusal::refused("not a toy mode")),
        }))
    }
}

thread_local! {
    /// The plugin a nesting toy calls from inside its own `deliver`, on the same thread.
    static INNER: RefCell<Option<Plugin<Export>>> = const { RefCell::new(None) };
    /// What the nested call answered, for the test to check the nesting it meant happened.
    static NESTED: RefCell<Option<Called>> = const { RefCell::new(None) };
}

/// One connector service on the call's own ticket: its failure, if any.
fn connector(instance: &Instance<'_, Held<Toy>, ExportKind>) -> Option<ConnFailure> {
    let host = instance.get()?.host()?;
    match host.connector(instance.ticket()).identity() {
        std::task::Poll::Ready(Err(e)) => Some(e),
        _ => None,
    }
}

fn nested() {
    let called = INNER.with(|p| {
        p.borrow()
            .as_ref()
            .map(|p| deliver(p).expect("the inner door answers"))
    });
    NESTED.with(|n| *n.borrow_mut() = called);
}

struct Deliver;
impl SafeSlot for Deliver {
    type Kind = ExportKind;
    type In = DeliverIn;
    type Out = OutHead;
    type State = Held<Toy>;
    fn call(
        instance: Instance<'_, Held<Toy>, ExportKind>,
        _: Lent<'_, DeliverIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let Some(mode) = instance.get().map(|h| h.life().0) else {
            return out.fail(Refusal::refused("no instance"));
        };
        match mode {
            Mode::Quiet => Outcome::Ready,
            Mode::ConnectorThenReady => {
                let _ = connector(&instance);
                Outcome::Ready
            }
            Mode::ConnectorThenRefused => match connector(&instance) {
                Some(e) => out.fail(Refusal::refused(e.to_string())),
                None => out.fail(Refusal::refused("the connector answered")),
            },
            Mode::ConnectorThenNestedThenReady => {
                if connector(&instance) != Some(ConnFailure::NoTicket) {
                    return out.fail(Refusal::refused("not handed NoTicket"));
                }
                nested();
                Outcome::Ready
            }
            Mode::NestedThenReady => {
                nested();
                Outcome::Ready
            }
        }
    }
}

struct Check;
impl SafeSlot for Check {
    type Kind = ExportKind;
    type In = CheckIn;
    type Out = CheckOut;
    type State = Held<Toy>;
    fn call(
        _: Instance<'_, Held<Toy>, ExportKind>,
        _: Lent<'_, CheckIn>,
        _: Out<'_, CheckOut>,
    ) -> Outcome {
        Outcome::Ready
    }
}

const TAIL: Tail = tail(&[ExportStream::Logs as u8], &[]);
const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    ..statement("ready-after-no-ticket-toy", "0.0.1", 4)
};
busbar_contract::plugin_door! {
    ops: busbar_contract::abi::export::Ops,
    statement: STATEMENT,
    lifecycle: life(Toy),
    kind_ops: {
        deliver: Safe<Deliver>, scrape: Safe<NoScrape<Toy>>,
        status: Safe<Quiet<Toy>>, check: Safe<Check>, serve: Safe<NoServe<Toy>>,
    },
}

// The toy states one `tcp` need, so a serving bind hands it a connector.
crate::needs_restated::tcp_restated!(networked, door);

extern "C" fn networked_door() -> &'static busbar_contract::abi::mechanism::door::Door {
    // SAFETY: `restate` answers one leaked, process-lived door.
    unsafe { &*networked() }
}

/// The toy, linked and opened in `mode`.
fn opened(mode: &str) -> Plugin<Export> {
    let d = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let row = LinkedRow::of(networked_door).expect("the toy door states itself");
    let p = load_linked::<Export>(
        &row,
        Bind {
            instance: Arc::from("export.ready-after-no-ticket"),
            max_inflight_cap: 4,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            // A serving bind with a table that opens nothing: the toy is handed a connector, so a
            // ticketless service is refused for its missing ticket.
            conns: ConnTable::Host(crate::dispatch::test_admissions(Arc::new(
                crate::needs_restated::Inert,
            ))),
        },
    )
    .expect("the toy door loads");
    let mut input: OpenIn = blank_in();
    input.head = in_head();
    input.settings = Blob {
        ptr: mode.as_ptr(),
        len: mode.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    input.generation = 1;
    let mut out: OpenOut = blank_out();
    out.head = out_head();
    let c = p.call(slot::OPEN, &mut Frame::new(input, out));
    assert_eq!(c.outcome, Outcome::Ready, "open {mode}");
    p
}

/// One ticketless `deliver`, through the real `Plugin::call`.
fn deliver(p: &Plugin<Export>) -> Option<Called> {
    let batch = b"{}\n";
    let mut input: DeliverIn = blank_in();
    input.head = in_head();
    input.stream = ExportStream::Logs as u8;
    input.batch = Blob {
        ptr: batch.as_ptr(),
        len: batch.len(),
        fmt: BLOB_JSONL,
        flags: 0,
    };
    Some(p.call(
        busbar_contract::abi::export::slot::DELIVER,
        &mut Frame::new(input, out_head()),
    ))
}

fn answered(c: &Called) -> (Outcome, String) {
    (
        c.outcome,
        String::from_utf8_lossy(c.error.as_deref().unwrap_or_default()).into_owned(),
    )
}

/// The nested call's answer, taken.
fn took_nested() -> Option<(Outcome, String)> {
    NESTED
        .with(|n| n.borrow_mut().take())
        .as_ref()
        .map(answered)
}

fn with_inner<R>(inner: &str, f: impl FnOnce() -> R) -> R {
    INNER.with(|p| *p.borrow_mut() = Some(opened(inner)));
    let r = f();
    INNER.with(|p| *p.borrow_mut() = None);
    r
}

#[test]
fn the_toy_connector_hands_a_ticketless_call_no_ticket() {
    // The control every pin below leans on: a ticketless connector service is refused for its
    // missing ticket, not for a missing connector.
    let p = opened("connector-then-refused");
    assert_eq!(
        answered(&deliver(&p).unwrap()),
        (Outcome::Refused, ConnFailure::NoTicket.to_string())
    );
}

#[test]
fn ready_after_the_sdk_answered_no_ticket_is_a_fault() {
    let p = opened("connector-then-ready");
    assert_eq!(deliver(&p).unwrap().outcome, Outcome::Fault);
}

#[test]
fn ready_with_no_io_is_still_ready() {
    let p = opened("quiet");
    assert_eq!(deliver(&p).unwrap().outcome, Outcome::Ready);
}

#[test]
fn refused_after_no_ticket_is_unchanged() {
    let p = opened("connector-then-refused");
    assert_eq!(deliver(&p).unwrap().outcome, Outcome::Refused);
}

#[test]
fn a_nested_quiet_call_does_not_clear_the_outer_calls_no_ticket() {
    // The outer call was handed NoTicket before a nested ticketless entry that does no I/O ran on
    // the same thread: the inner entry must not wipe what the outer one was handed.
    let outer = with_inner("quiet", || {
        let p = opened("connector-then-nested-then-ready");
        deliver(&p).unwrap()
    });
    assert_eq!(took_nested(), Some((Outcome::Ready, String::new())));
    assert_eq!(outer.outcome, Outcome::Fault);
}

#[test]
fn a_nested_calls_no_ticket_is_not_the_outer_calls() {
    // The nested ticketless entry is handed NoTicket and answers REFUSED; the outer call, which
    // did no I/O of its own, answers READY and must stay READY.
    let outer = with_inner("connector-then-refused", || {
        let p = opened("nested-then-ready");
        deliver(&p).unwrap()
    });
    assert_eq!(
        took_nested(),
        Some((Outcome::Refused, ConnFailure::NoTicket.to_string()))
    );
    assert_eq!(outer.outcome, Outcome::Ready);
}
