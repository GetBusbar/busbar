// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Adversarial completion-ACK metadata at an actual MCP descriptor's raw DRIVE
//! boundary. The actual image owns OPEN/CLOSE and every unchanged operation.
//! No settings script or business-session interpreter is installed.

use crate::dispatch::kinds::plane::{open_door, Plane};
use crate::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_contract::abi::mechanism::call::{Blob, InHead, Outcome, RawOutcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::{OpsHead, ReleaseIn};
use busbar_contract::abi::mechanism::ticket::CompletionHandle;
use busbar_contract::abi::plane::{
    OnPieceIn, OnPieceOut, Ops, PlaneCancelIn, PlaneCancelOut, PlaneDriveIn, PlaneDriveOut,
    PlaneOpenIn, ProjectIn, ProjectOut,
};
use busbar_contract::abi::sdk::completion_retirement::{self as wire, Domain, Handle, Retirement};
use busbar_contract::abi::sdk::services::Services;
use busbar_contract::services::{
    Caller, DiskDest, HookAsk, Later, NestAsk, Ran, Reading, RecordsList, Snapshot, Stored,
    TrustKeyRef,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::Poll;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum Defect {
    Pending,
    Ready,
    Failed,
    Short,
    Malformed,
    Owner,
    Nonce,
    Cancel,
    PendingOverflow,
    PendingNeeded,
    Session,
}
static NEXT: AtomicU8 = AtomicU8::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());
struct State {
    services: Services,
    retirement: Retirement,
    defect: Defect,
    completed: bool,
    releases: usize,
    leases: HashMap<u64, Box<[u8]>>,
    next_lease: u64,
    resumes: usize,
    notify: bool,
}
static STATES: OnceLock<Mutex<HashMap<u64, State>>> = OnceLock::new();
fn states() -> &'static Mutex<HashMap<u64, State>> {
    STATES.get_or_init(Default::default)
}
fn actual_ops() -> Ops {
    // SAFETY: actual_mcp retains its validated descriptor and live image.
    unsafe {
        crate::actual_mcp::door()
            .ops()
            .cast::<Ops>()
            .read_unaligned()
    }
}
fn guarded(f: impl FnOnce() -> RawOutcome) -> RawOutcome {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .unwrap_or(RawOutcome::of(Outcome::Fault))
}
extern "C" fn open(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> RawOutcome {
    guarded(|| {
        let real = actual_ops().head.open.expect("actual MCP OPEN");
        // SAFETY: forwarding the loader's exact valid PlaneOpen frames to actual MCP.
        let result = unsafe { real(instance, input, output) };
        if result.outcome() != Outcome::Ready {
            return result;
        }
        // SAFETY: loader's initialized PlaneOpen frame remains borrowed during OPEN.
        let input = unsafe { &*input.cast::<PlaneOpenIn>() };
        // SAFETY: actual OPEN accepted the host's live advertised table.
        let services =
            unsafe { Services::from_raw(&*input.open.host) }.expect("actual bound host services");
        let defect = match NEXT.load(SeqCst) {
            0 => Defect::Pending,
            1 => Defect::Ready,
            2 => Defect::Failed,
            3 => Defect::Short,
            4 => Defect::Malformed,
            5 => Defect::Owner,
            6 => Defect::Nonce,
            7 => Defect::Cancel,
            8 => Defect::PendingOverflow,
            9 => Defect::PendingNeeded,
            _ => Defect::Session,
        };
        states().lock().unwrap().insert(
            input.open.head.host.handle,
            State {
                services,
                retirement: Retirement::default(),
                defect,
                completed: false,
                releases: 0,
                leases: HashMap::new(),
                next_lease: u64::MAX,
                resumes: 0,
                notify: true,
            },
        );
        result
    })
}
extern "C" fn drive(
    _: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> RawOutcome {
    guarded(|| {
        // SAFETY: loader supplies initialized, aligned typed DRIVE frames.
        let (input, output) = unsafe {
            (
                &*input.cast::<PlaneDriveIn>(),
                &mut *output.cast::<PlaneDriveOut>(),
            )
        };
        let mut all = states().lock().unwrap();
        let state = all
            .get_mut(&input.drive.head.host.handle)
            .expect("actual OPEN captured services");
        // The preceding answer lease must have been released before reentry.
        if !state.leases.is_empty() {
            return RawOutcome::of(Outcome::Fault);
        }
        let ext = input.drive.head.extensions;
        // SAFETY: loader lends the exact extension allocation for this crossing.
        let ext = if ext.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(ext.ptr, ext.len) }
        };
        if input.drive.head.flags & busbar_contract::abi::mechanism::call::FLAG_RESUME != 0 {
            state.resumes += 1;
        }
        if state
            .retirement
            .begin(input.drive.head.host, input.drive.driver, ext)
            .is_err()
        {
            return RawOutcome::of(Outcome::Fault);
        }
        let mut service_pending = false;
        if !state.completed {
            let handle = CompletionHandle {
                ticket: input.drive.driver,
                seq: 0,
                ..CompletionHandle::ZERO
            };
            let mut bytes = [0; 16];
            match state
                .services
                .records_get(handle, "last", b"drive", &mut bytes)
            {
                Poll::Ready(Ok(Some(bytes))) if bytes == b"completed" => {
                    state.completed = true;
                    state.notify = true;
                    if state
                        .retirement
                        .consumed(Handle {
                            domain: Domain::Host,
                            seq: 0,
                        })
                        .is_err()
                    {
                        return RawOutcome::of(Outcome::Fault);
                    }
                }
                Poll::Pending
                    if matches!(
                        state.defect,
                        Defect::PendingOverflow | Defect::PendingNeeded | Defect::Session
                    ) =>
                {
                    service_pending = true
                }
                _ => return RawOutcome::of(Outcome::Fault),
            }
        }
        let mut ack = state
            .retirement
            .acknowledgement(0)
            .expect("valid retirement queue");
        if let Some(ref mut ack) = ack {
            if state.defect == Defect::Owner {
                ack.capability.owner.handle ^= 1;
            }
            if state.defect == Defect::Nonce {
                ack.capability.nonce += 1;
            }
        }
        if state.defect == Defect::Cancel {
            ack = None;
        }
        let bytes = ack
            .map(|ack| wire::append_ack(&[], &ack).expect("complete ACK framing"))
            .unwrap_or_else(|| b"answer-owner".to_vec())
            .into_boxed_slice();
        let outcome = match state.defect {
            _ if service_pending => Outcome::Pending,
            Defect::Ready | Defect::Session => Outcome::Ready,
            Defect::Failed | Defect::Short => Outcome::Failed,
            _ if state.retirement.queued() => Outcome::Pending,
            _ => Outcome::Ready,
        };
        let lease = state.next_lease;
        state.next_lease -= 1;
        output.head.extensions = Blob::ZERO;
        output.head.error = busbar_contract::abi::mechanism::call::AbiStr::ZERO;
        if state.retirement.queued() && state.defect != Defect::Cancel {
            output.head.extensions = Blob {
                ptr: bytes.as_ptr(),
                len: bytes.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            };
        }
        if output.head.extensions.len == 0 {
            output.head.error = busbar_contract::abi::mechanism::call::AbiStr {
                ptr: bytes.as_ptr(),
                len: bytes.len(),
            };
        }
        output.head.lease = lease;
        output.head.outcome = RawOutcome::of(outcome);
        output.sessions_written =
            if matches!(state.defect, Defect::Malformed | Defect::PendingOverflow) {
                input.sessions_cap as u32 + 1
            } else {
                0
            };
        output.sessions_needed = if matches!(state.defect, Defect::Short | Defect::PendingNeeded) {
            input.sessions_cap as u32 + 1
        } else {
            0
        };
        if state.defect == Defect::Session && state.notify {
            if input.sessions_cap == 0 || input.sessions_buf.is_null() {
                return RawOutcome::of(Outcome::Fault);
            }
            // SAFETY: the actual host DRIVE frame lends sessions_cap initialized writable IDs.
            unsafe {
                input.sessions_buf.write(5);
            }
            output.sessions_written = 1;
            state.notify = false;
        }
        state.leases.insert(lease, bytes);
        RawOutcome::of(outcome)
    })
}
extern "C" fn release(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> RawOutcome {
    guarded(|| {
        // SAFETY: loader supplies an initialized RELEASE input.
        let request = unsafe { &*input.cast::<ReleaseIn>() };
        let mut all = states().lock().unwrap();
        if let Some(state) = all.get_mut(&request.head.host.handle) {
            if state.leases.remove(&request.lease).is_some() {
                state.releases += 1;
                // SAFETY: RELEASE output is the exclusive OutHead supplied by the loader.
                unsafe {
                    (*output.cast::<busbar_contract::abi::mechanism::call::OutHead>()).outcome =
                        RawOutcome::of(Outcome::Ready);
                }
                return RawOutcome::of(Outcome::Ready);
            }
        }
        drop(all);
        // SAFETY: unchanged RELEASE forwards the actual image's lease and exact frames.
        unsafe { actual_ops().head.release.expect("actual MCP RELEASE")(instance, input, output) }
    })
}
extern "C" fn project(
    _: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> RawOutcome {
    guarded(|| {
        // SAFETY: the loader supplies the initialized exclusive PROJECT ABI frames.
        let (input, output) = unsafe {
            (
                &*input.cast::<ProjectIn>(),
                &mut *output.cast::<ProjectOut>(),
            )
        };
        let all = states().lock().unwrap();
        let state = all
            .get(&input.head.host.handle)
            .expect("actual MCP OPEN captured its services");
        let handle = CompletionHandle {
            ticket: busbar_contract::abi::mechanism::ticket::Ticket::NONE,
            seq: 0,
            ..CompletionHandle::ZERO
        };
        if !matches!(
            state.services.entitled(handle, "door:project-scope"),
            Ok(true)
        ) {
            return RawOutcome::of(Outcome::Fault);
        }
        output.head.outcome = RawOutcome::of(Outcome::Ready);
        RawOutcome::of(Outcome::Ready)
    })
}
extern "C" fn pending_piece(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> RawOutcome {
    guarded(|| {
        // SAFETY: initialized exclusive ON_PIECE output supplied by the dispatcher.
        unsafe {
            (*output.cast::<OnPieceOut>()).head.outcome = RawOutcome::of(Outcome::Pending);
        }
        RawOutcome::of(Outcome::Pending)
    })
}
extern "C" fn cancel(
    _: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> RawOutcome {
    guarded(|| {
        // SAFETY: these are the loader's initialized, exclusive plane CANCEL frames.
        let (input, output) = unsafe {
            (
                &*input.cast::<PlaneCancelIn>(),
                &mut *output.cast::<PlaneCancelOut>(),
            )
        };
        let mut all = states().lock().unwrap();
        let state = all
            .get_mut(&input.cancel.head.host.handle)
            .expect("bound actual MCP instance");
        if state.defect == Defect::Session {
            output.cancel.head.outcome = RawOutcome::of(Outcome::Ready);
            output.cancel.disposition = busbar_contract::abi::plane::CANCEL_ABORTED;
            return RawOutcome::of(Outcome::Ready);
        }
        let ack = state
            .retirement
            .acknowledgement(0)
            .unwrap()
            .expect("unconsumed driver receipt");
        let bytes = wire::append_ack(&[], &ack).unwrap().into_boxed_slice();
        let lease = state.next_lease;
        state.next_lease -= 1;
        output.cancel.head.extensions = Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        output.cancel.head.lease = lease;
        output.cancel.head.outcome = RawOutcome::of(Outcome::Ready);
        output.cancel.disposition = busbar_contract::abi::plane::CANCEL_ABORTED;
        state.leases.insert(lease, bytes);
        RawOutcome::of(Outcome::Ready)
    })
}
extern "C" fn close(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> RawOutcome {
    guarded(|| {
        // SAFETY: the loader supplies a valid CLOSE head until this callback returns.
        let host = unsafe { (*input.cast::<InHead>()).host.handle };
        if states()
            .lock()
            .unwrap()
            .get(&host)
            .is_some_and(|s| !s.leases.is_empty())
        {
            return RawOutcome::of(Outcome::Fault);
        }
        // SAFETY: no boundary-owned answer remains lent; exact actual instance and CLOSE frames.
        let result =
            unsafe { actual_ops().head.close.expect("actual MCP CLOSE")(instance, input, output) };
        if result.outcome() == Outcome::Ready {
            // Services callbacks are no longer retained beyond their actual instance lifetime.
            states().lock().unwrap().remove(&host);
        }
        result
    })
}
extern "C" fn door() -> &'static Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    let addr = DOOR.get_or_init(|| {
        let real = *crate::actual_mcp::door();
        let ops = actual_ops();
        let head = OpsHead {
            open: Some(open),
            drive: Some(drive),
            release: Some(release),
            cancel: Some(cancel),
            close: Some(close),
            ..ops.head
        };
        let ops = Box::leak(Box::new(Ops {
            head,
            on_piece: Some(pending_piece),
            project: Some(project),
            ..ops
        }));
        // SAFETY: actual retained Statement/table except the three exact ABI boundary controls.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..real.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: immutable descriptor and retained actual image remain process-live.
    unsafe { &*(*addr as *const Door) }
}
#[derive(Default)]
struct Provider {
    calls: AtomicUsize,
    defer: bool,
    waiting: Mutex<Vec<busbar_contract::services::Later>>,
    attributed: Mutex<Vec<(String, Option<u64>, String)>>,
}
impl busbar_contract::services::HostServices for Provider {
    fn now(&self) -> Reading {
        let wall_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        let mono_ns = ORIGIN
            .get_or_init(Instant::now)
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        Reading { wall_ns, mono_ns }
    }
    fn dest_judge(&self, _dest: &str, _class: u32, _flags: u32, _later: Option<Later>) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn records_list(&self, _caller: &Caller, _list: RecordsList, _later: Later) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn records_claim(
        &self,
        _caller: &Caller,
        _kind: &str,
        _key: &[u8],
        _ttl_ms: u64,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn sign(&self, _caller: &Caller, _data: &[u8]) -> Stored {
        Stored::refused("not served by this completion-ACK boundary control")
    }
    fn trust_sight(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _hash: &str,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn trust_unreached(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        Stored::refused("not served by this completion-ACK boundary control")
    }
    fn trust_sight_item(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: &str,
        _digest: &str,
    ) -> Stored {
        Stored::refused("not served by this completion-ACK boundary control")
    }
    fn trust_decide(
        &self,
        _caller: &Caller,
        _key: TrustKeyRef<'_>,
        _expected: Option<&str>,
        _approve: bool,
    ) -> Stored {
        Stored::refused("not served by this completion-ACK boundary control")
    }
    fn trust_state(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        Stored::refused("not served by this completion-ACK boundary control")
    }
    fn trust_serves(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: Option<&str>,
        _digest: Option<&str>,
    ) -> Stored {
        Stored::refused("not served by this completion-ACK boundary control")
    }
    fn trust_due(&self, _caller: &Caller) -> Stored {
        Stored::refused("not served by this completion-ACK boundary control")
    }
    fn trust_verify(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _payload: &[u8],
        _signatures: &[u8],
    ) -> Stored {
        Stored::refused("not served by this completion-ACK boundary control")
    }
    fn entitlement_check(&self, caller: &Caller, unit: Option<u64>, target: &str) -> Stored {
        self.attributed.lock().unwrap().push((
            caller.instance.to_string(),
            unit,
            target.to_string(),
        ));
        Stored::ready(busbar_contract::abi::host::service::ENTITLED)
    }
    fn session_emit(&self, _caller: &Caller, _session: u64, _bytes: &[u8]) -> Stored {
        Stored::refused("not served by this completion-ACK boundary control")
    }
    fn ticket_mint(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _ttl_secs: u64,
        _record: &[u8],
    ) -> Stored {
        Stored::refused("not served by this completion-ACK boundary control")
    }
    fn ticket_take(&self, _caller: &Caller, _unit: Option<u64>) -> Stored {
        Stored::refused("not served by this completion-ACK boundary control")
    }
    fn random_fill(&self, _len: u64) -> Stored {
        Stored::refused("not served by this completion-ACK boundary control")
    }
    fn records_secret(&self, _kind: &str, _id: &str, _later: Later) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn unit_nest(&self, _caller: &Caller, _unit: Option<u64>, _ask: NestAsk, _later: Later) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn work_open(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _kind: &str,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn work_find(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _reference: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn work_settle(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn work_resume(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn disk_append(&self, _dest: &DiskDest, _bytes: Vec<u8>, _later: Later) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn verify_lookup(&self, _caller: &Caller, _key: &[u8], _later: Later) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn verify_store(&self, _caller: &Caller, _key: &[u8], _entry: &[u8], _ttl_ms: u64) -> Stored {
        Stored::refused("not served by this completion-ACK boundary control")
    }
    fn content_scan(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _content: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn hook_call(&self, _caller: &Caller, _unit: Option<u64>, _ask: HookAsk, _later: Later) -> Ran {
        Ran::Now(Stored::refused(
            "not served by this completion-ACK boundary control",
        ))
    }
    fn snapshot_read(&self, _caller: &Caller, _scope: u32) -> Snapshot {
        Snapshot::Refused("not served by this completion-ACK boundary control")
    }

    fn records_get(
        &self,
        _: &busbar_contract::services::Caller,
        kind: &str,
        key: &[u8],
        later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        assert_eq!((kind, key), ("last", b"drive".as_slice()));
        self.calls.fetch_add(1, SeqCst);
        if self.defer {
            self.waiting.lock().unwrap().push(later);
            return busbar_contract::services::Ran::Later;
        }
        let mut result = crate::dispatch::Stored::ready(busbar_contract::abi::host::service::FOUND);
        result.bytes = b"completed".to_vec();
        result
            .spans
            .push(busbar_contract::abi::host::service::ItemSpan {
                key: busbar_contract::abi::mechanism::call::Span::ZERO,
                value: busbar_contract::abi::mechanism::call::Span { offset: 0, len: 9 },
            });
        busbar_contract::services::Ran::Now(result)
    }
}
fn until(mut predicate: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(Instant::now() < end, "actual driver did not settle");
        std::thread::sleep(Duration::from_millis(1));
    }
}
#[test]
fn automatic_driver_checks_ack_before_releasing_its_answer_lease() {
    let _serial = TEST_LOCK.lock().unwrap();
    for defect in [
        Defect::Pending,
        Defect::Ready,
        Defect::Failed,
        Defect::Short,
        Defect::Malformed,
        Defect::Owner,
        Defect::Nonce,
        Defect::PendingOverflow,
        Defect::PendingNeeded,
    ] {
        NEXT.store(defect as u8, SeqCst);
        let provider = Arc::new(Provider {
            defer: matches!(defect, Defect::PendingOverflow | Defect::PendingNeeded),
            ..Provider::default()
        });
        let dispatcher = Dispatcher::with_services(DispatchConfig::default(), provider.clone());
        let row = LinkedRow::of(door).expect("actual MCP descriptor plus hostile ABI metadata");
        let plugin = load_linked::<Plane>(
            &row,
            Bind {
                instance: format!("ack-{}", defect as u8).into(),
                max_inflight_cap: 8,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::Probe,
            },
        )
        .unwrap();
        open_door(&plugin, b"{}", b"{}", None).expect("actual MCP lifecycle opens");
        let host = plugin.inner.ctx().handle;
        let driver = dispatcher.driver(&plugin, 0).unwrap();
        crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
        if matches!(defect, Defect::Ready | Defect::Pending) {
            until(|| {
                plugin.inner.driven.answers() == 2
                    && states()
                        .lock()
                        .unwrap()
                        .get(&host)
                        .is_some_and(|s| s.releases == 2)
            });
            assert_eq!(
                plugin
                    .inner
                    .driven
                    .answered_after(1, Duration::from_secs(5)),
                Some(Outcome::Ready)
            );
            assert_eq!(dispatcher.services().held(), 0);
            assert_eq!(dispatcher.services().held.held(driver), 0);
        } else {
            assert_eq!(
                plugin
                    .inner
                    .driven
                    .answered_after(0, Duration::from_secs(5)),
                Some(Outcome::Fault)
            );
            until(|| {
                states()
                    .lock()
                    .unwrap()
                    .get(&host)
                    .is_some_and(|s| s.releases == 1)
            });
            assert_eq!(
                dispatcher.services().held(),
                1,
                "rejected main answer cannot consume its completion"
            );
            assert!(plugin.inner.driven.drain().is_empty());
        }
        assert_eq!(provider.calls.load(SeqCst), 1);
        dispatcher.recycle(driver);
        drop(plugin);
        drop(dispatcher);
        until(|| !states().lock().unwrap().contains_key(&host));
    }
}

#[test]
fn canceling_an_actual_pending_crossing_cannot_ack_its_drivers_result() {
    let _serial = TEST_LOCK.lock().unwrap();
    use crate::dispatch::{in_head, out_head, Frame};
    use busbar_contract::abi::mechanism::call::DeadlineClass;
    use busbar_contract::abi::plane::{slot, FROM_CALLER};
    NEXT.store(Defect::Cancel as u8, SeqCst);
    let provider = Arc::<Provider>::default();
    let dispatcher = Dispatcher::with_services(DispatchConfig::default(), provider.clone());
    let plugin = load_linked::<Plane>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            instance: "cancel-driver-ack".into(),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Probe,
        },
    )
    .unwrap();
    open_door(&plugin, b"{}", b"{}", None).unwrap();
    let host = plugin.inner.ctx().handle;
    let driver = dispatcher.driver(&plugin, 0).unwrap();
    crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
    until(|| {
        plugin.inner.driven.answers() == 1
            && states()
                .lock()
                .unwrap()
                .get(&host)
                .is_some_and(|s| s.releases == 1)
    });
    assert_eq!(dispatcher.services().held(), 1);
    let session = dispatcher.mint(0).unwrap();
    // SAFETY: the ABI input/output consist of zero-valid plain C frame fields.
    let (mut input, mut output): (OnPieceIn, OnPieceOut) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    input.head = in_head();
    input.from = FROM_CALLER;
    input.stream = 5;
    output.head = out_head();
    let reply = dispatcher.submit(
        &plugin,
        session,
        slot::ON_PIECE,
        Frame::new(input, output),
        DeadlineClass::Call,
        0,
    );
    until(|| dispatcher.is_pending(session));
    dispatcher.drop_client(session);
    assert_eq!(
        reply.wait(Duration::from_secs(5)).unwrap().outcome,
        Outcome::Fault
    );
    until(|| {
        states()
            .lock()
            .unwrap()
            .get(&host)
            .is_some_and(|s| s.releases == 2)
    });
    assert_eq!(
        dispatcher.services().held(),
        1,
        "CANCEL has no authority over the driver's delivered result"
    );
    assert_eq!(provider.calls.load(SeqCst), 1);
    dispatcher.recycle(session);
    dispatcher.recycle(driver);
    drop(plugin);
    drop(dispatcher);
    until(|| !states().lock().unwrap().contains_key(&host));
}

#[test]
fn a_pending_driver_delivers_ids_resumes_and_retires_late_service_custody() {
    use crate::dispatch::{in_head, out_head, Frame};
    use busbar_contract::abi::mechanism::call::DeadlineClass;
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, TickIn, TickOut};
    use busbar_contract::abi::plane::{slot, CANCEL_ABORTED, FROM_CALLER};
    let _serial = TEST_LOCK.lock().unwrap();
    NEXT.store(Defect::Session as u8, SeqCst);
    let provider = Arc::new(Provider {
        defer: true,
        ..Provider::default()
    });
    let dispatcher = Dispatcher::with_services(DispatchConfig::default(), provider.clone());
    let plugin = load_linked::<Plane>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            instance: "pending-driver-service".into(),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Probe,
        },
    )
    .unwrap();
    open_door(&plugin, b"{}", b"{}", None).unwrap();
    let host = plugin.inner.ctx().handle;
    let driver = dispatcher.driver(&plugin, 0).unwrap();
    crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
    until(|| {
        plugin.inner.driven.answers() == 1
            && states()
                .lock()
                .unwrap()
                .get(&host)
                .is_some_and(|s| s.releases == 1)
    });
    assert_eq!(plugin.inner.driven.drain(), vec![5]);
    assert_eq!(dispatcher.services().held.held(driver), 1);
    assert_eq!(dispatcher.services().held(), 1);
    crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
    until(|| {
        plugin.inner.driven.answers() == 2
            && states()
                .lock()
                .unwrap()
                .get(&host)
                .is_some_and(|s| s.releases == 2)
    });
    assert!(plugin.inner.driven.drain().is_empty());
    assert_eq!(states().lock().unwrap().get(&host).unwrap().resumes, 1);
    assert_eq!(provider.calls.load(SeqCst), 1);
    assert_eq!(dispatcher.services().held.held(driver), 1);
    let completed = || {
        let mut result = crate::dispatch::Stored::ready(busbar_contract::abi::host::service::FOUND);
        result.bytes = b"completed".to_vec();
        result
            .spans
            .push(busbar_contract::abi::host::service::ItemSpan {
                key: busbar_contract::abi::mechanism::call::Span::ZERO,
                value: busbar_contract::abi::mechanism::call::Span { offset: 0, len: 9 },
            });
        result
    };
    provider.waiting.lock().unwrap().pop().unwrap()(completed());
    assert_eq!(
        plugin
            .inner
            .driven
            .answered_after(2, Duration::from_secs(5)),
        Some(Outcome::Ready)
    );
    until(|| {
        states()
            .lock()
            .unwrap()
            .get(&host)
            .is_some_and(|s| s.releases == 3)
    });
    assert_eq!(plugin.inner.driven.drain(), vec![5]);
    assert_eq!(dispatcher.services().held.held(driver), 0);
    assert_eq!(dispatcher.services().held(), 0);
    states().lock().unwrap().get_mut(&host).unwrap().completed = false;
    crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
    until(|| {
        plugin.inner.driven.answers() == 4
            && states()
                .lock()
                .unwrap()
                .get(&host)
                .is_some_and(|s| s.releases == 4)
    });
    assert_eq!(provider.calls.load(SeqCst), 2);
    assert!(plugin.inner.driven.drain().is_empty());
    let session = dispatcher.mint(0).unwrap();
    // SAFETY: these ABI frames consist of zero-valid integers and pointer/length pairs.
    let (mut input, mut output): (OnPieceIn, OnPieceOut) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    input.head = in_head();
    input.from = FROM_CALLER;
    input.stream = 5;
    output.head = out_head();
    let reply = dispatcher.submit(
        &plugin,
        session,
        slot::ON_PIECE,
        Frame::new(input, output),
        DeadlineClass::Call,
        0,
    );
    until(|| dispatcher.is_pending(session));
    dispatcher.drop_client(session);
    let canceled = reply.wait(Duration::from_secs(5)).unwrap();
    assert_eq!(canceled.disposition, Some(CANCEL_ABORTED));
    dispatcher.recycle(session);
    let late = provider.waiting.lock().unwrap().pop().unwrap();
    dispatcher.recycle(driver);
    let barrier = dispatcher.mint(0).unwrap();
    let tick = || {
        Frame::new(
            TickIn {
                head: in_head(),
                now_ns: 0,
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 0,
            },
        )
    };
    assert_eq!(
        dispatcher
            .submit(&plugin, barrier, life::TICK, tick(), DeadlineClass::Call, 0)
            .wait(Duration::from_secs(5))
            .unwrap()
            .outcome,
        Outcome::Ready
    );
    assert_eq!(dispatcher.services().held(), 0);
    assert_eq!(dispatcher.services().held.held(driver), 0);
    late(completed());
    assert_eq!(
        dispatcher
            .submit(&plugin, barrier, life::TICK, tick(), DeadlineClass::Call, 0)
            .wait(Duration::from_secs(5))
            .unwrap()
            .outcome,
        Outcome::Ready
    );
    assert_eq!(plugin.inner.driven.answers(), 4);
    assert!(plugin.inner.driven.drain().is_empty());
    dispatcher.recycle(barrier);
    drop(plugin);
    drop(dispatcher);
    until(|| !states().lock().unwrap().contains_key(&host));
}

#[test]
fn project_attributes_the_actual_host_service_call_to_its_unit() {
    use crate::dispatch::{in_head, out_head, Frame};
    use busbar_contract::abi::hook::SignalEntry;
    use busbar_contract::abi::mechanism::call::AbiStr;
    use busbar_contract::abi::plane::slot;
    let _serial = TEST_LOCK.lock().unwrap();
    NEXT.store(Defect::Pending as u8, SeqCst);
    let provider = Arc::<Provider>::default();
    let dispatcher = Dispatcher::with_services(DispatchConfig::default(), provider.clone());
    let plugin = load_linked::<Plane>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            instance: "the-instance".into(),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Probe,
        },
    )
    .unwrap();
    open_door(&plugin, b"{}", b"{}", None).expect("actual MCP lifecycle opens");
    let host = plugin.inner.ctx().handle;
    for unit in [73, 0] {
        // SAFETY: plain ABI integers and pointer/length fields admit zero initialization.
        let (mut input, mut output, mut signals): (ProjectIn, ProjectOut, [SignalEntry; 2]) =
            unsafe { (std::mem::zeroed(), std::mem::zeroed(), std::mem::zeroed()) };
        let mut arena = [0_u8; 64];
        input.head = in_head();
        input.unit = unit;
        input.target = AbiStr::over(b"door:project-scope");
        input.body = Blob {
            ptr: b"abc".as_ptr(),
            len: 3,
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        input.signals_buf = signals.as_mut_ptr();
        input.signals_cap = signals.len();
        input.arena_buf = arena.as_mut_ptr();
        input.arena_cap = arena.len();
        output.head = out_head();
        let mut frame = Frame::new(input, output);
        assert_eq!(
            plugin.call(slot::PROJECT, &mut frame).outcome,
            Outcome::Ready
        );
    }
    assert_eq!(
        *provider.attributed.lock().unwrap(),
        vec![
            ("the-instance".into(), Some(73), "door:project-scope".into()),
            ("the-instance".into(), None, "door:project-scope".into())
        ]
    );
    drop(plugin);
    drop(dispatcher);
    until(|| !states().lock().unwrap().contains_key(&host));
}
