// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The loader's former SDK connector/wire controls, at their actual private SDK boundary.
//! These are HostTables ABI controls; they do not claim actual TCP/TLS transport qualification.
use crate::abi::host::conn::connector::{ConnectorSlots, EstablishIn, IoIn, StreamIn};
use crate::abi::host::service::ServiceOut;
use crate::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use crate::abi::mechanism::ticket::{CompletionHandle, HostCtx, HostTables, Ticket};
use crate::abi::sdk::conn::{ConnFailure, Host};
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
    opened: Vec<(u32, String)>,
    closed: usize,
    written: Vec<u8>,
    reads: HashMap<CompletionHandle, (usize, usize)>,
    chunks: usize,
    pending_reads: usize,
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
        let refuse = state(|s| {
            s.opened.push((input.need, target));
            s.refuse
        });
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
        state(|s| s.written.extend_from_slice(bytes));
        (*out).len = input.len as u64;
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
fn host(refuse: bool) -> Host {
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
            wake: None,
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
