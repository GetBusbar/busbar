// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The loader's former SDK connector/wire controls, at their actual private SDK boundary.

use crate::abi::host::conn::connector::{ConnectorSlots, EstablishIn, IoIn, StreamIn};
use crate::abi::host::service::ServiceOut;
use crate::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use crate::abi::mechanism::ticket::{CompletionHandle, HostCtx, HostTables, Ticket};
use crate::abi::sdk::conn::ConnFailure;
use crate::abi::sdk::store::op::Parked;
use crate::abi::sdk::store::wire::{drive, Wire};
use crate::abi::sdk::store::{Op, Step};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::task::Poll;

const TICKET: Ticket = Ticket {
    slot: 21,
    generation: 7,
};
const REFUSAL: &[u8] = b"the connection was refused";
#[derive(Default)]
struct Crossings {
    refuse: bool,
    wait: bool,
    opened: Vec<(u32, String)>,
    closed: usize,
    written: Vec<u8>,
    reads: HashMap<CompletionHandle, (usize, usize)>,
    chunks: usize,
    pending_reads: usize,
    partial_write: bool,
    write_handles: Vec<CompletionHandle>,
    wakes: Vec<(Ticket, usize)>,
}
thread_local! {static CROSSINGS: RefCell<Crossings> = RefCell::new(Crossings::default());}
fn state<T>(f: impl FnOnce(&mut Crossings) -> T) -> T {
    CROSSINGS.with(|s| f(&mut s.borrow_mut()))
}

extern "C" fn establish(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK lends this exact EstablishIn and exclusive initialized ServiceOut.
    unsafe {
        let input = &*input.cast::<EstablishIn>();
        let target = if input.target.len == 0 {
            String::new()
        } else {
            String::from_utf8(
                std::slice::from_raw_parts(input.target.ptr, input.target.len).to_vec(),
            )
            .expect("target UTF-8")
        };
        let (refuse, wait) = state(|s| {
            s.opened.push((input.need, target));
            (s.refuse, s.wait)
        });
        if wait {
            return RawOutcome::of(Outcome::Pending);
        }
        if refuse {
            (*out).error = AbiStr::over(REFUSAL);
            RawOutcome::of(Outcome::Refused)
        } else {
            (*out).value = 42;
            RawOutcome::of(Outcome::Ready)
        }
    }
}
extern "C" fn close(_: HostCtx, input: *const c_void, _: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the actual connector lends StreamIn for this close callback.
    let input = unsafe { &*input.cast::<StreamIn>() };
    assert_eq!(input.stream, 42);
    state(|s| s.closed += 1);
    RawOutcome::of(Outcome::Ready)
}
extern "C" fn write(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK lends IoIn and its initialized read-only write prefix for this crossing.
    unsafe {
        let input = &*input.cast::<IoIn>();
        let bytes = std::slice::from_raw_parts(input.buf, input.len);
        let count = state(|s| {
            let count = if s.partial_write {
                bytes.len().min(1)
            } else {
                bytes.len()
            };
            s.written.extend_from_slice(&bytes[..count]);
            s.write_handles.push(input.head.handle);
            count
        });
        (*out).len = count as u64;
    }
    RawOutcome::of(Outcome::Ready)
}
extern "C" fn read(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK lends IoIn and its writable read prefix, retained across Pending.
    unsafe {
        let input = &*input.cast::<IoIn>();
        state(|s| {
            if let Some(&(ptr, len)) = s.reads.get(&input.head.handle) {
                assert_eq!(
                    (ptr, len),
                    (input.buf as usize, input.len),
                    "resumption retains the same live read loan"
                );
                let chunk: &[u8] = match s.chunks {
                    0 => b"echo ",
                    1 => b"hello\n",
                    _ => b"",
                };
                assert!(input.len >= chunk.len());
                std::ptr::copy_nonoverlapping(chunk.as_ptr(), input.buf, chunk.len());
                (*out).len = chunk.len() as u64;
                s.chunks += 1;
                RawOutcome::of(Outcome::Ready)
            } else {
                s.reads
                    .insert(input.head.handle, (input.buf as usize, input.len));
                s.pending_reads += 1;
                RawOutcome::of(Outcome::Pending)
            }
        })
    }
}
extern "C" fn wake(_: HostCtx, ticket: Ticket) {
    state(|s| s.wakes.push((ticket, s.written.len())));
}
fn host(refuse: bool) -> Host {
    host_config(refuse, false)
}
fn host_config(refuse: bool, with_wake: bool) -> Host {
    state(|s| {
        *s = Crossings {
            refuse,
            ..Crossings::default()
        }
    });
    // SAFETY: ConnectorSlots consists only of integer headers and optional function pointers.
    let mut table: ConnectorSlots = unsafe { std::mem::zeroed() };
    table.size = size_of::<ConnectorSlots>() as u32;
    table.slots = crate::abi::host::conn::connector::SERVICES;
    table.establish = Some(establish);
    table.close = Some(close);
    table.write = Some(write);
    table.read = Some(read);
    // SAFETY: Host snapshots the initialized table, whose callbacks remain static and inspect
    // only live actual SDK inputs. Per-test observations are confined to this thread.
    unsafe {
        Host::from_raw(&HostTables {
            size: size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx::NONE,
            wake: with_wake.then_some(wake),
            conns: &table,
            services: std::ptr::null(),
            io: std::ptr::null(),
        })
    }
}

#[test]
fn a_store_declaring_a_tcp_need_receives_a_connector() {
    let host = host(false);
    let mut op = Op::enter(TICKET, Some(&host), None, None);
    assert_eq!(
        op.checkout(0, Some("db.internal:5432")),
        Poll::Ready(Ok(42))
    );
    assert_eq!(
        state(|s| s.opened.clone()),
        vec![(0, "db.internal:5432".into())]
    );
    assert_eq!(
        op.checkout(0, Some("db.internal:5432")),
        Poll::Ready(Ok(42))
    );
    assert_eq!(
        state(|s| s.opened.len()),
        1,
        "one op reuses its one actual SDK checkout"
    );
    drop(op.into_parked());
}
#[test]
fn a_store_connects_over_the_hosts_table_at_open() {
    let host = host(false);
    let mut op = Op::enter(TICKET, Some(&host), None, None);
    assert_eq!(
        op.checkout(0, Some("db.internal:5432")),
        Poll::Ready(Ok(42))
    );
    drop(op.into_parked());
    assert_eq!(
        state(|s| s.opened.clone()),
        vec![(0, "db.internal:5432".into())]
    );
    assert_eq!(
        state(|s| s.closed),
        1,
        "the settled connect step hands its stream back"
    );
}
#[test]
fn an_unreachable_backend_fails_the_load_with_the_stores_message() {
    let host = host(true);
    let mut op = Op::enter(TICKET, Some(&host), None, None);
    assert_eq!(
        op.checkout(0, Some("db.internal:5432")),
        Poll::Ready(Err(ConnFailure::Refused(
            String::from_utf8(REFUSAL.to_vec()).unwrap()
        )))
    );
    drop(op.into_parked());
    assert_eq!(
        state(|s| s.closed),
        0,
        "no failed checkout acquires stream authority"
    );
}
#[test]
fn a_wire_body_pends_on_its_reads_and_answers_the_backends_reply() {
    let host = host(false);
    for _ in 0..2 {
        state(|s| {
            s.chunks = 0;
            s.reads.clear();
        });
        let before = state(|s| s.pending_reads);
        let mut parked: Option<Parked> = None;
        let mut result = None;
        for _ in 0..8 {
            let mut op = Op::enter(TICKET, Some(&host), parked.take(), None);
            let answer = drive(&mut op, |wire: Wire| {
                Box::pin(async move {
                    wire.connect(0, Some("db.internal:5432")).await?;
                    wire.write_all(b"hello\n").await?;
                    loop {
                        if let Some(line) = wire.input(|bytes| {
                            let end = bytes.iter().position(|&b| b == b'\n')?;
                            Some(
                                String::from_utf8(bytes.drain(..=end).collect())
                                    .expect("reply UTF-8"),
                            )
                        }) {
                            return Ok::<_, ConnFailure>(line.trim_end().to_string());
                        }
                        if wire.fill().await? == 0 {
                            return Err(ConnFailure::Failed("backend closed".into()));
                        }
                    }
                })
            });
            let held = op.into_parked();
            match answer {
                Step::Ready(answer) => {
                    result = Some(answer);
                    drop(held);
                    break;
                }
                Step::Pending { .. } => parked = Some(held),
            }
        }
        assert_eq!(result, Some(Ok("echo hello".into())));
        assert_eq!(
            state(|s| s.pending_reads) - before,
            2,
            "both split reads really pend before answering"
        );
    }
    assert_eq!(state(|s| s.written.clone()), b"hello\nhello\n");
    assert_eq!(
        state(|s| s.closed),
        2,
        "each completed wire body releases its stream"
    );
}

#[test]
fn pending_on_the_connector_with_no_service_in_flight_is_fault() {
    use crate::abi::sdk::store::v4::door::park as pending_parked;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    struct DropProbe(Arc<AtomicUsize>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let host = host(false);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut idle = Op::enter(TICKET, Some(&host), None, None);
    idle.park(DropProbe(drops.clone()));
    assert!(
        pending_parked(idle, 0).is_none(),
        "the production Store pending guard returns Fault when no service or timed wake arms it"
    );
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "the actual rejected pending context drops its owned state before Fault leaves the guard"
    );
    assert!(
        state(|s| s.opened.is_empty()),
        "the Fault did not make up a connector attempt"
    );

    let drops = Arc::new(AtomicUsize::new(0));
    let mut timed = Op::enter(TICKET, Some(&host), None, None);
    timed.park(DropProbe(drops.clone()));
    let parked = pending_parked(timed, 1).expect("a timed wake arms this real ticket");
    assert_eq!(
        drops.load(Ordering::SeqCst),
        0,
        "accepted wait retains its state"
    );
    drop(parked);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "cancelling the retained wait drops once"
    );
    assert!(
        pending_parked(Op::detached(), 1).is_none(),
        "a wake cannot give a no-ticket call pending authority"
    );

    state(|s| s.wait = true);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut waiting = Op::enter(TICKET, Some(&host), None, None);
    waiting.park(DropProbe(drops.clone()));
    assert_eq!(waiting.checkout(0, Some("db.internal:5432")), Poll::Pending);
    let parked = pending_parked(waiting, 0)
        .expect("the actual pending HostTables service arms a zero-wake wait");
    assert_eq!(
        drops.load(Ordering::SeqCst),
        0,
        "pending service retains the owned context"
    );
    drop(parked);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn always_ready_stream_yields_keeps_partial_writes_and_never_replays_ready_io() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    for (cancel, with_wake) in [(false, true), (true, true), (false, false)] {
        let host = host_config(false, with_wake);
        state(|s| s.partial_write = true);
        let starts = Arc::new(AtomicUsize::new(0));
        let mut parked = None;
        let mut finished = false;
        for turn in 0..64 {
            let mut op = Op::enter(TICKET, Some(&host), parked.take(), None);
            let started = starts.clone();
            let before = state(|s| s.wakes.len());
            let answer = drive(&mut op, move |wire| {
                started.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    wire.connect(0, Some("ready.internal:6379")).await?;
                    let payload: Vec<u8> = (0..=255).collect();
                    wire.write_all(&payload).await?;
                    for byte in 0..96u8 {
                        wire.write_all(&[byte]).await?;
                    }
                    wire.close().await;
                    Ok::<_, ConnFailure>(())
                })
            });
            match answer {
                Step::Pending { .. } => {
                    assert_eq!(
                        state(|s| s.wakes.len()),
                        before + 1,
                        "wake is latched before returning Pending"
                    );
                    assert!(state(|s| s
                        .wakes
                        .last()
                        .is_some_and(|(ticket, _)| *ticket == TICKET)));
                    if turn == 0 {
                        assert!(
                            state(|s| s.written.len()) < 256,
                            "partial native write yields before completion"
                        );
                    }
                    let pending = op.into_parked();
                    if cancel {
                        drop(pending);
                        finished = true;
                        break;
                    }
                    parked = Some(pending);
                }
                Step::Ready(result) => {
                    result.unwrap();
                    if with_wake {
                        assert!(turn > 0, "an always-ready stream must yield");
                    } else {
                        assert_eq!(turn, 0);
                    }
                    drop(op.into_parked());
                    finished = true;
                    break;
                }
            }
        }
        assert!(finished);
        assert_eq!(
            starts.load(Ordering::SeqCst),
            1,
            "resume retains the exact body"
        );
        state(|s| {
            assert_eq!(s.opened.len(), 1);
            assert_eq!(s.closed, 1, "yield/cancel retain one checkout owner");
            let unique: std::collections::HashSet<_> = s.write_handles.iter().copied().collect();
            assert_eq!(
                unique.len(),
                s.write_handles.len(),
                "no already-ready I/O handle is replayed"
            );
            if !cancel {
                let expected: Vec<u8> = (0..=255).chain(0..96).collect();
                assert_eq!(s.written, expected);
                if with_wake {
                    assert!(
                        s.wakes.iter().any(|(_, bytes)| *bytes > 256),
                        "separate ready write requests also yield"
                    );
                } else {
                    assert!(s.wakes.is_empty());
                }
            }
        });
    }
}

type Host = crate::abi::sdk::conn::Host<FixtureKind>;

type FixtureKind = crate::plugin::markers::StoreKind;
