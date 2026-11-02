// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{AbiStr, DeadlineClass, OutHead, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorParts, KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{slot, ValidateIn};
use busbar_contract::abi::mechanism::rendering::read;
use busbar_contract::abi::mechanism::{KindCode, DOOR_SYMBOL};
use busbar_contract::abi::sdk::door::RawDoorFn;
use busbar_contract::abi::transport::{FramePiece, TransportTail};
use busbar_contract::auth::LoginOutcome;
use busbar_contract::auth_calls::LoginCall;

use crate::dispatch::call::{Answering, Pending, Ticketed};
use crate::dispatch::kinds::transport::Transport;
use crate::dispatch::lifecycle::{open_frame, release, validate_frame};
use crate::dispatch::load::{enter_door, read_door, validate_door};
use crate::dispatch::{
    in_head, load_dropped, load_linked, now_ns, out_head, Bind, ConnTable, DispatchConfig,
    Dispatcher, Done, Frame, LinkedRow, LoadError, NoSink, Plugin, NO_BLOB,
};

const WITHIN: Duration = Duration::from_secs(5);

fn tcp_path() -> PathBuf {
    std::env::var_os("BUSBAR_TEST_TCP_CDYLIB")
        .map(PathBuf::from)
        .expect("BUSBAR_TEST_TCP_CDYLIB must name the qualified real TCP image")
}

fn tcp_entry() -> RawDoorFn {
    static IMAGE: OnceLock<(libloading::Library, RawDoorFn)> = OnceLock::new();
    IMAGE
        .get_or_init(|| {
            let lib =
                crate::dlopen_on_worker(tcp_path().as_os_str()).expect("the real TCP image loads");
            // SAFETY: the qualified image exports the mechanism's typed door symbol. IMAGE keeps
            // the library and all of its descriptor data live until process exit.
            let entry = unsafe {
                *lib.get::<RawDoorFn>(DOOR_SYMBOL)
                    .expect("the real TCP door")
            };
            (lib, entry)
        })
        .1
}

fn tcp_parts() -> DoorParts {
    let ptr = enter_door(tcp_entry());
    validate_door::<Transport>(ptr).expect("the unmodified real TCP descriptor validates");
    read_door(ptr, Some(KindCode::Transport))
        .expect("the real TCP head validates")
        .0
}

fn descriptor(parts: DoorParts) -> &'static Door {
    // SAFETY: all retained pointers originate in the process-held real image or explicitly
    // leaked immutable metadata below. Only checked numeric metadata is made incompatible;
    // no malformed operation table is entered.
    Box::leak(Box::new(unsafe { Door::__from_parts(parts) }))
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig::default()))
}

fn bind(d: &Dispatcher) -> Bind {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    Bind {
        instance: format!(
            "ordinary-loader-negative-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
        .into(),
        max_inflight_cap: 16,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::NoNeeds,
    }
}

#[test]
fn actual_transport_kind_abi_versions_above_and_below_are_refused() {
    let real = tcp_parts();
    let host = KindCode::Transport.abi_version();
    for stated in [host - 1, host + 1] {
        let door = descriptor(DoorParts {
            kind_abi: stated,
            ..real
        });
        assert_eq!(
            validate_door::<Transport>(door).err(),
            Some(LoadError::KindAbi {
                kind: KindCode::Transport,
                door: stated,
                host
            })
        );
    }
}

#[test]
fn actual_transport_incompatible_layouts_are_refused_with_the_rebuild_reason() {
    let real = tcp_parts();
    let host = KindCode::Transport.layout_fingerprint();
    for stated in [host ^ 1, 0] {
        let door = descriptor(DoorParts {
            layout: stated,
            ..real
        });
        let refused = validate_door::<Transport>(door)
            .err()
            .expect("the wrong layout is refused");
        let LoadError::KindLayout {
            plugin,
            kind,
            stated: got,
            host: want,
        } = &refused
        else {
            panic!("wrong refusal: {refused:?}");
        };
        assert!(!plugin.is_empty());
        assert_eq!((*kind, *got, *want), (KindCode::Transport, stated, host));
        assert!(refused
            .to_string()
            .contains("rebuild against this busbar-contract"));
    }
}

#[test]
fn actual_transport_frame_piece_stride_is_checked_before_use() {
    let real = tcp_parts();
    // SAFETY: tcp_parts validated the complete live Statement and transport tail.
    let st = unsafe { real.statement.read_unaligned() };
    // SAFETY: the validated transport tail is complete and kept live by IMAGE.
    let tail = unsafe { st.kind_tail.cast::<TransportTail>().read_unaligned() };
    let host = std::mem::size_of::<FramePiece>() as u32;
    let stated = host - 8;
    let tail = Box::leak(Box::new(TransportTail {
        frame_piece_size: stated,
        ..tail
    }));
    let st = Box::leak(Box::new(Statement {
        kind_tail: std::ptr::from_ref(tail).cast::<KindTailHead>(),
        ..st
    }));
    let door = descriptor(DoorParts {
        statement: st,
        ..real
    });
    let refused = validate_door::<Transport>(door)
        .err()
        .expect("another stride is refused");
    let LoadError::FramePieceSize {
        plugin,
        stated: got,
        host: want,
    } = refused
    else {
        panic!("wrong refusal: {refused:?}");
    };
    assert!(!plugin.is_empty());
    assert_eq!((got, want), (stated, host));
}

#[test]
fn actual_transport_is_refused_as_each_other_kind() {
    let ptr = enter_door(tcp_entry());
    for want in KindCode::ALL
        .into_iter()
        .filter(|k| *k != KindCode::Transport)
    {
        assert_eq!(
            read_door(ptr, Some(want)).err(),
            Some(LoadError::WrongKind {
                door: KindCode::Transport,
                want
            })
        );
    }
}

extern "C" fn another_version() -> *const Door {
    let real = tcp_parts();
    // SAFETY: tcp_parts validated this process-held Statement.
    let st = unsafe { real.statement.read_unaligned() };
    let st = Box::leak(Box::new(Statement {
        version: AbiStr {
            ptr: b"999.0.0".as_ptr(),
            len: 7,
        },
        ..st
    }));
    descriptor(DoorParts {
        statement: st,
        ..real
    })
}

#[test]
fn actual_door_and_valid_but_different_row_or_manifest_statements_must_match() {
    let d = dispatcher();
    let actual = LinkedRow::of_raw(tcp_entry()).expect("the actual TCP Statement renders");
    let other = LinkedRow::of_raw(another_version).expect("the changed version renders");
    read(&other.statement).expect("the changed Statement is independently well formed");
    assert_ne!(actual.statement, other.statement);
    drop(load_linked::<Transport>(&actual, bind(&d)).expect("the honest linked row loads"));
    drop(
        load_dropped::<Transport>(&tcp_path(), &actual.statement, bind(&d))
            .expect("the honest dropped manifest loads"),
    );
    let lying = LinkedRow {
        statement: other.statement.clone(),
        door: tcp_entry(),
    };
    assert_eq!(
        load_linked::<Transport>(&lying, bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
    assert_eq!(
        load_dropped::<Transport>(&tcp_path(), &other.statement, bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
    let lying_door = LinkedRow {
        statement: actual.statement,
        door: another_version,
    };
    assert_eq!(
        load_linked::<Transport>(&lying_door, bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
}

static READY_CALLS: AtomicU64 = AtomicU64::new(0);
const READY_FAILURE: &[u8] = b"ordinary negative: discovery refused";

unsafe extern "C" fn ready_fails(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
    READY_CALLS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: the dispatcher supplies an exclusive OutHead for this READY callback; the error
    // bytes are static and no answer lease is claimed.
    unsafe {
        let head = &mut *out.cast::<OutHead>();
        head.outcome = RawOutcome::of(Outcome::Failed);
        head.error = AbiStr {
            ptr: READY_FAILURE.as_ptr(),
            len: READY_FAILURE.len(),
        };
    }
    RawOutcome::of(Outcome::Failed)
}

#[test]
fn actual_transport_lifecycle_surrounds_one_failed_ready_without_retry() {
    let d = dispatcher();
    let mut validated = validate_door::<Transport>(enter_door(tcp_entry())).unwrap();
    validated.ready = Some(ready_fails);
    let p = Plugin::<Transport>::bind(validated, None, bind(&d)).unwrap();
    let mut open = open_frame(crate::dispatch::lifecycle::blob(
        b"{}",
        busbar_contract::abi::mechanism::call::BLOB_JSON,
        0,
    ));
    assert_eq!(p.call(slot::OPEN, &mut open).outcome, Outcome::Ready);
    let before = p.inner.crossings.load(Ordering::Relaxed);
    let called = READY_CALLS.load(Ordering::SeqCst);
    assert!(p.has_ready());
    assert_eq!(
        p.ready(&d, WITHIN),
        Err(format!(
            "plugin '{}' ready failed: {}",
            p.name(),
            std::str::from_utf8(READY_FAILURE).unwrap()
        ))
    );
    assert_eq!(READY_CALLS.load(Ordering::SeqCst), called + 1);
    assert_eq!(p.inner.crossings.load(Ordering::Relaxed), before + 1);
    let mut close = Frame::new(in_head(), out_head());
    assert_eq!(p.call(slot::CLOSE, &mut close).outcome, Outcome::Ready);
    assert_eq!(p.inner.crossings.load(Ordering::Relaxed), before + 2);
}

static FAULT_CALLS: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn raw_fault(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
    FAULT_CALLS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: the dispatcher supplies the exclusive OutHead for VALIDATE. This callback writes
    // exactly the mechanism's Fault marker and retains no pointers or lease.
    unsafe {
        (*out.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Fault);
    }
    RawOutcome::of(Outcome::Fault)
}

struct FaultAnswer(Plugin<Transport>);

impl Answering<ValidateIn, OutHead> for FaultAnswer {
    type Out = LoginOutcome;

    fn answer(
        &mut self,
        done: Done<ValidateIn, OutHead>,
        _: &mut Ticketed<ValidateIn, OutHead>,
    ) -> Option<LoginOutcome> {
        assert_eq!(done.outcome, Outcome::Fault);
        assert!(
            done.frame.is_some(),
            "the submitted real dispatcher call completed"
        );
        release(&self.0, done.lease);
        Some(LoginOutcome::Reject)
    }
}

#[test]
fn counted_raw_fault_crosses_the_dispatcher_and_sets_the_generic_login_call_flag() {
    let d = dispatcher();
    let mut validated = validate_door::<Transport>(enter_door(tcp_entry())).unwrap();
    validated.slots[slot::VALIDATE as usize] = raw_fault;
    let p = Plugin::<Transport>::bind(validated, None, bind(&d)).unwrap();
    let before = FAULT_CALLS.load(Ordering::SeqCst);
    let mut call = Ticketed::mint(&d, 0).expect("the dispatcher mints the actual call");
    call.submit(
        &p,
        slot::VALIDATE,
        validate_frame(NO_BLOB),
        DeadlineClass::Call,
        now_ns() + WITHIN.as_nanos() as u64,
        Arc::new(()),
    );
    let mut pending = Pending::new(call, FaultAnswer(p));
    assert!(!pending.any_fault());
    assert!(!LoginCall::faulted(&pending));
    let until = Instant::now() + WITHIN;
    let answer = loop {
        if let Some(answer) = LoginCall::settled(&mut pending) {
            break answer;
        }
        assert!(Instant::now() < until, "the raw Fault call must settle");
        std::thread::sleep(Duration::from_millis(1));
    };
    assert!(matches!(answer, LoginOutcome::Reject));
    assert_eq!(FAULT_CALLS.load(Ordering::SeqCst), before + 1);
    assert!(pending.any_fault());
    assert!(LoginCall::faulted(&pending));
    assert!(matches!(
        LoginCall::settled(&mut pending),
        Some(LoginOutcome::Reject)
    ));
    assert!(LoginCall::faulted(&pending));
    assert_eq!(FAULT_CALLS.load(Ordering::SeqCst), before + 1);
}
