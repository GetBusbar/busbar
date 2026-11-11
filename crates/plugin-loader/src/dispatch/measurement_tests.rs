// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::dispatch::{
    self, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, Kind, LinkedRow, NoSink, Plugin,
};
use busbar_contract::abi::measurement::{BillableClass, UNITS_REPORTED_MICROS};
use busbar_contract::abi::mechanism::{
    call::{InHead, Op, OutHead, Outcome, RawOutcome, FLAG_RESUME},
    door::{Door, DoorFn},
    lifecycle::{slot, TickIn, TickOut, ValidateIn},
};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Mutex, OnceLock,
};
use std::time::{Duration, Instant};

thread_local! { static REPORT: RefCell<UnitCount> = const { RefCell::new(UnitCount {class:0,source:UNITS_REPORTED_MICROS,amount:0}) }; }
extern "C" fn report(
    _: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> RawOutcome {
    // SAFETY: all replaced slots lead with the common heads.
    let (input, output) = unsafe { (&*input.cast::<InHead>(), &mut *output.cast::<OutHead>()) };
    let mode = if input.extensions.len == 1 && !input.extensions.ptr.is_null() {
        unsafe { *input.extensions.ptr }
    } else {
        0
    };
    if input.op == slot::CANCEL {
        output.outcome = RawOutcome::of(Outcome::Ready);
        return output.outcome;
    }
    if mode == 8 {
        output.outcome = RawOutcome::of(Outcome::Ready);
        return output.outcome;
    }
    REPORT.with(|count| {
        let mut count = count.borrow_mut();
        *count = UnitCount {
            class: 0,
            source: if mode == 1 { 99 } else { UNITS_REPORTED_MICROS },
            amount: input.measurement_revision * 1_000_001,
        };
        output.envelope.measurements = MeasurementBatch {
            revision: input.measurement_revision + u64::from(mode == 3),
            counts: std::ptr::from_ref(&*count),
            counts_len: if mode == 2 { 65 } else { 1 },
        };
    });
    let outcome = match mode {
        4 => Outcome::Failed,
        5 if input.flags & FLAG_RESUME == 0 => Outcome::Pending,
        6 => Outcome::Pending,
        _ => Outcome::Ready,
    };
    output.outcome = RawOutcome::of(outcome);
    output.outcome
}
extern "C" fn decide(
    _: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> RawOutcome {
    use busbar_contract::abi::hook::{DecideIn, DecideOut, VERB_ABSTAIN};
    let (i, o) = unsafe { (&*input.cast::<DecideIn>(), &mut *output.cast::<DecideOut>()) };
    if i.order_cap == 0 {
        o.order_needed = 1;
        o.head.envelope.measurements = MeasurementBatch {
            revision: i.head.measurement_revision,
            counts: std::ptr::null(),
            counts_len: 0,
        };
        o.head.outcome = RawOutcome::of(Outcome::Failed);
    } else {
        let result = report(std::ptr::null_mut(), input, output);
        o.verbs = VERB_ABSTAIN;
        return result;
    }
    o.head.outcome
}

fn measured(original: &'static Door) -> &'static Door {
    let mut parts = original.parts();
    // SAFETY: the neutral fixtures expose valid complete descriptors and tables.
    let mut statement = unsafe { *parts.statement };
    let class = Box::leak(Box::new(BillableClass {
        class: busbar_contract::abi::sdk::door::abi_str("raw"),
        family: busbar_contract::abi::sdk::door::abi_str("units"),
    }));
    statement.measurement_classes = class;
    statement.measurement_classes_len = 1;
    parts.statement = Box::leak(Box::new(statement));
    let bytes = unsafe { (*parts.ops).size } as usize;
    let table =
        Box::leak(vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())].into_boxed_slice());
    unsafe {
        std::ptr::copy_nonoverlapping(
            parts.ops.cast::<u8>(),
            table.as_mut_ptr().cast::<u8>(),
            bytes,
        );
        let ops = table
            .as_mut_ptr()
            .cast::<u8>()
            .add(dispatch::FIRST_SLOT)
            .cast::<Option<Op>>();
        for slot in [slot::VALIDATE, slot::TICK, slot::CANCEL, slot::DRIVE] {
            ops.add(slot as usize).write(Some(report));
        }
        if statement.kind == busbar_contract::abi::mechanism::KindCode::Hook as u32 {
            ops.add(busbar_contract::abi::hook::slot::DECIDE as usize)
                .write(Some(decide));
        }
        parts.ops = table.as_ptr().cast();
        Box::leak(Box::new(Door::__from_parts(parts)))
    }
}
macro_rules! fixture {
    ($name:ident, $original:path) => {
        extern "C" fn $name() -> &'static Door {
            static DOOR: OnceLock<usize> = OnceLock::new();
            let ptr = *DOOR.get_or_init(|| measured($original()) as *const Door as usize);
            unsafe { &*(ptr as *const Door) }
        }
    };
}
fixture!(store, crate::neutral_store::door);
fixture!(secret, crate::neutral_secret::door);
fixture!(auth, crate::neutral_auth::door);
fixture!(
    hook,
    crate::hook_door_conformance_tests::hook_door_plugin::conforming::door
);
fixture!(export, crate::neutral_export::door);
fixture!(plane, crate::neutral_plane::door);
fixture!(transport, crate::neutral_transport::door);

#[derive(Default)]
struct Host {
    unavailable: AtomicBool,
    conflict: AtomicBool,
    maintenance: AtomicBool,
    bindings: Mutex<Vec<Binding>>,
    contexts: Mutex<Vec<Option<u64>>>,
    operations: Mutex<Vec<Arc<Work>>>,
    probe: Mutex<Option<Arc<dyn Fn() -> u32 + Send + Sync>>>,
}
struct Work {
    revision: AtomicU64,
    captured: Mutex<Vec<CapturedBatch>>,
    released: AtomicU64,
    finished: AtomicU64,
    conflict: bool,
    maintenance: bool,
    host: std::sync::Weak<Host>,
}
impl Operation for Work {
    fn is_maintenance(&self) -> bool {
        self.maintenance
    }
    fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }
    fn capture(&self, batch: CapturedBatch) -> Result<(), Refusal> {
        if self.conflict {
            return Err(Refusal::Conflict);
        }
        self.captured.lock().unwrap().push(batch);
        self.revision.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    fn released(&self, terminal: bool) {
        if let Some(host) = self.host.upgrade() {
            if let Some(probe) = host.probe.lock().unwrap().as_ref() {
                assert_eq!(
                    probe(),
                    0,
                    "persistence handoff must follow invocation capacity release"
                );
            }
        }
        if terminal {
            self.finished.fetch_add(1, Ordering::AcqRel);
        } else {
            self.released.fetch_add(1, Ordering::AcqRel);
        }
    }
}
struct AuthorityOf(Arc<Host>);
impl Authority for AuthorityOf {
    fn reserve(
        &self,
        binding: &Binding,
        context: Option<&Context>,
        _: u32,
    ) -> Result<Arc<dyn Operation>, Refusal> {
        if self.0.unavailable.load(Ordering::Acquire) {
            return Err(Refusal::Unavailable);
        }
        if context.is_some_and(|context| context.downcast_ref::<u64>() != Some(&42)) {
            return Err(Refusal::Unavailable);
        }
        self.0
            .contexts
            .lock()
            .unwrap()
            .push(context.and_then(|c| c.downcast_ref::<u64>().copied()));
        self.0.bindings.lock().unwrap().push(binding.clone());
        let work = Arc::new(Work {
            revision: AtomicU64::new(if self.0.maintenance.load(Ordering::Acquire) {
                0
            } else {
                1
            }),
            captured: Mutex::default(),
            released: AtomicU64::new(0),
            finished: AtomicU64::new(0),
            conflict: self.0.conflict.load(Ordering::Acquire),
            maintenance: self.0.maintenance.load(Ordering::Acquire),
            host: Arc::downgrade(&self.0),
        });
        self.0.operations.lock().unwrap().push(work.clone());
        Ok(work)
    }
}
fn rig<K: Kind>(door: DoorFn, installed: bool) -> (Dispatcher, Plugin<K>, Arc<Host>) {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let host = Arc::new(Host::default());
    if installed {
        assert!(d
            .set_measurement_authority(Arc::new(AuthorityOf(host.clone())))
            .is_ok());
    }
    let p = dispatch::load_linked::<K>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            instance: "configured-measurement".into(),
            max_inflight_cap: 4,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::Probe,
        },
    )
    .unwrap();
    let weak = Arc::downgrade(&p.inner);
    *host.probe.lock().unwrap() =
        Some(Arc::new(move || weak.upgrade().map_or(0, |i| i.inflight())));
    (d, p, host)
}
fn validate<K: Kind>(p: &Plugin<K>, mode: u8) -> dispatch::Called {
    let mut input = ValidateIn {
        head: dispatch::in_head(),
        settings: dispatch::NO_BLOB,
        err_buf: std::ptr::null_mut(),
        err_cap: 0,
    };
    input.head.extensions = dispatch::lifecycle::blob(
        std::slice::from_ref(&mode),
        busbar_contract::abi::mechanism::call::BLOB_OCTETS,
        0,
    );
    p.call(slot::VALIDATE, &mut Frame::new(input, dispatch::out_head()))
}
fn crosses<K: Kind>(door: DoorFn) {
    let (_d, p, host) = rig::<K>(door, true);
    assert_eq!(validate(&p, 0).outcome, Outcome::Ready);
    assert_eq!(validate(&p, 0).outcome, Outcome::Ready);
    let binding = &host.bindings.lock().unwrap()[0];
    assert_eq!(binding.caller.kind(), K::CODE);
    assert_eq!(
        binding.caller.namespace().as_ref(),
        "configured-measurement"
    );
    assert_eq!(binding.classes[0].class, "raw");
    assert_eq!(binding.statement_digest, p.statement_digest());
    for operation in host.operations.lock().unwrap().iter() {
        let reports = operation.captured.lock().unwrap();
        assert_eq!(reports[0].counts[0].amount, 1_000_001);
        assert_eq!(
            reports[0].counts[0].count().unwrap().to_string(),
            "1.000001"
        );
        assert_eq!(operation.finished.load(Ordering::Acquire), 1);
    }
}
#[test]
fn common_measurement_crosses_all_seven_kind_identities_and_copies_ffi_storage() {
    use dispatch::kinds::*;
    crosses::<store_v4::StoreV4>(store);
    crosses::<secret::Secret>(secret);
    crosses::<auth::Auth>(auth);
    crosses::<hook::Hook>(hook);
    crosses::<export::Export>(export);
    crosses::<plane::Plane>(plane);
    crosses::<transport::Transport>(transport);
}
#[test]
fn measurement_authority_capacity_and_unknown_context_refuse_before_callback() {
    use dispatch::kinds::secret::Secret;
    let (_d, p, _) = rig::<Secret>(secret, false);
    assert_eq!(validate(&p, 0).outcome, Outcome::Refused);
    assert_eq!(p.test_invocations(), (0, 0));
    let (_d, p, host) = rig::<Secret>(secret, true);
    host.unavailable.store(true, Ordering::Release);
    assert_eq!(validate(&p, 0).outcome, Outcome::Refused);
    host.unavailable.store(false, Ordering::Release);
    with_context(Some(Arc::new("untrusted-context")), || {
        assert_eq!(validate(&p, 0).outcome, Outcome::Refused)
    });
    assert_eq!(p.test_invocations(), (0, 0));
}
#[test]
fn measurement_malformed_overlimit_wrong_revision_and_custody_conflict_fault() {
    for mode in [1, 2, 3] {
        let (_d, p, host) = rig::<dispatch::kinds::secret::Secret>(secret, true);
        assert_eq!(validate(&p, mode).outcome, Outcome::Fault);
        assert!(host.operations.lock().unwrap()[0]
            .captured
            .lock()
            .unwrap()
            .is_empty());
    }
    let (_d, p, host) = rig::<dispatch::kinds::secret::Secret>(secret, true);
    host.conflict.store(true, Ordering::Release);
    assert_eq!(validate(&p, 0).outcome, Outcome::Fault);
}
#[test]
fn measurement_accepted_counts_survive_failed_kind_answer_and_instance_drop() {
    let (d, p, host) = rig::<dispatch::kinds::secret::Secret>(secret, true);
    assert_eq!(validate(&p, 4).outcome, Outcome::Fault);
    drop(p);
    drop(d);
    assert_eq!(
        host.operations.lock().unwrap()[0]
            .captured
            .lock()
            .unwrap()
            .len(),
        1
    );
}
fn tick(mode: &u8) -> Frame<TickIn, TickOut> {
    let mut head = dispatch::in_head();
    head.extensions = dispatch::lifecycle::blob(
        std::slice::from_ref(mode),
        busbar_contract::abi::mechanism::call::BLOB_OCTETS,
        0,
    );
    Frame::new(
        TickIn { head, now_ns: 0 },
        TickOut {
            head: dispatch::out_head(),
            next_tick_ns: 0,
        },
    )
}
fn until(mut check: impl FnMut() -> bool) {
    let start = Instant::now();
    while !check() {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::yield_now();
    }
}
#[test]
fn measurement_pending_resume_and_cancel_keep_host_operation() {
    for mode in [5, 6] {
        let (d, p, host) = rig::<dispatch::kinds::secret::Secret>(secret, true);
        assert_eq!(
            crate::door_both_ways::open(&p, b"{}").outcome,
            Outcome::Ready
        );
        // The asynchronous dispatcher may retire an earlier reservation while a later CLOSE
        // owns capacity; global instance occupancy cannot identify that prior operation.
        *host.probe.lock().unwrap() = None;
        let ticket = d.mint(0).unwrap();
        let reply = d.submit(
            &p,
            ticket,
            slot::TICK,
            tick(&mode),
            busbar_contract::abi::mechanism::call::DeadlineClass::Call,
            0,
        );
        until(|| {
            host.operations
                .lock()
                .unwrap()
                .iter()
                .any(|op| !op.captured.lock().unwrap().is_empty())
        });
        let operation = host.operations.lock().unwrap().last().unwrap().clone();
        assert_eq!(operation.released.load(Ordering::Acquire), 0);
        if mode == 5 {
            dispatch::ticket::Waking::of(p.inner.wake)
                .unwrap()
                .wake(ticket);
            assert_eq!(
                reply.wait(Duration::from_secs(5)).unwrap().outcome,
                Outcome::Ready
            );
            assert_eq!(
                operation
                    .captured
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|b| b.revision)
                    .collect::<Vec<_>>(),
                vec![1, 2]
            );
        } else {
            drop(reply);
            until(|| operation.finished.load(Ordering::Acquire) == 1);
        }
        assert_eq!(
            operation.captured.lock().unwrap()[0].counts[0].amount,
            1_000_001
        );
        d.recycle(ticket);
        assert_eq!(crate::door_both_ways::close(&p).outcome, Outcome::Ready);
    }
}
#[tokio::test]
async fn measurement_task_context_survives_yield_and_explicit_system_scope() {
    scope(Some(Arc::new(42u64)), async {
        tokio::task::yield_now().await;
        assert_eq!(current_context().unwrap().downcast_ref::<u64>(), Some(&42));
        with_context(None, || assert!(current_context().is_none()));
        assert!(current_context().is_some());
    })
    .await;
    assert!(current_context().is_none());
}

#[test]
fn measurement_short_reply_pins_cursor_and_only_success_accrues() {
    use busbar_contract::abi::hook::{slot as hook_slot, DecideIn, DecideOut};
    let (_d, p, host) = rig::<dispatch::kinds::hook::Hook>(hook, true);
    assert_eq!(
        crate::door_both_ways::open(&p, br#"{"reject_over_messages":3}"#).outcome,
        Outcome::Ready
    );
    let mut input: DecideIn = unsafe { std::mem::zeroed() };
    let mut output: DecideOut = unsafe { std::mem::zeroed() };
    input.head = dispatch::in_head();
    output.head = dispatch::out_head();
    let mut frame = Frame::new(input, output);
    let short = p.call(hook_slot::DECIDE, &mut frame);
    assert_eq!(short.outcome, Outcome::Failed);
    let token = short.recall.unwrap();
    let work = host.operations.lock().unwrap().last().unwrap().clone();
    assert!(work.captured.lock().unwrap().is_empty());
    assert_eq!(work.finished.load(Ordering::Acquire), 0);
    let mut order = 0u32;
    frame.input.order_buf = &mut order;
    frame.input.order_cap = 1;
    assert_eq!(
        p.recall(token, hook_slot::DECIDE, &mut frame).outcome,
        Outcome::Ready
    );
    assert_eq!(work.captured.lock().unwrap()[0].revision, 1);
    assert_eq!(work.finished.load(Ordering::Acquire), 1);
    assert_eq!(crate::door_both_ways::close(&p).outcome, Outcome::Ready);
}

#[test]
fn measurement_signed_declaration_mismatch_is_refused_at_admission() {
    let (_d, p, _) = rig::<dispatch::kinds::secret::Secret>(secret, true);
    let mut row = LinkedRow::of(secret).unwrap();
    let index = row
        .statement
        .windows(3)
        .position(|bytes| bytes == b"raw")
        .unwrap();
    row.statement[index..index + 3].copy_from_slice(b"bad");
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let result = dispatch::load_linked::<dispatch::kinds::secret::Secret>(
        &row,
        Bind {
            instance: "other".into(),
            max_inflight_cap: 1,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::Probe,
        },
    );
    assert!(matches!(
        result,
        Err(dispatch::LoadError::StatementMismatch)
    ));
    assert_eq!(p.measurement_binding().classes[0].class, "raw");
}

#[cfg(unix)]
#[test]
fn measurement_native_c_dropin_uses_common_header_and_rejects_old_mechanism() {
    use std::process::Command;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let directory = std::env::temp_dir().join(format!(
        "busbar-measurement-native-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).unwrap();
    struct Clean(std::path::PathBuf);
    impl Drop for Clean {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _clean = Clean(directory.clone());
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let build = |old: bool| {
        let library = directory.join(if old {
            "old.dylib"
        } else {
            "measurement.dylib"
        });
        let mut command = Command::new("cc");
        command
            .args([
                "-std=c11", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
            ])
            .arg("-I")
            .arg(crate_dir.join("../busbar-contract/include"))
            .arg(crate_dir.join("tests/fixtures/measurement_door.c"))
            .arg("-o")
            .arg(&library);
        if old {
            command.arg("-DWITNESS_MECHANISM=3");
        }
        let result = command.output().expect("C compiler for native ABI fixture");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        library
    };
    let path = build(false);
    let stated = dispatch::rendering_of_library(&path).unwrap().unwrap();
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let host = Arc::new(Host::default());
    assert!(d
        .set_measurement_authority(Arc::new(AuthorityOf(host.clone())))
        .is_ok());
    let bind = || Bind {
        instance: "native".into(),
        max_inflight_cap: 1,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    };
    let p =
        dispatch::load_dropped::<dispatch::kinds::secret::Secret>(&path, &stated, bind()).unwrap();
    assert_eq!(validate(&p, 0).outcome, Outcome::Ready);
    assert_eq!(
        host.operations.lock().unwrap()[0].captured.lock().unwrap()[0].counts[0].amount,
        1_500_001
    );
    let old = build(true);
    assert!(matches!(
        dispatch::load_dropped::<dispatch::kinds::secret::Secret>(&old, &stated, bind()),
        Err(dispatch::LoadError::Mechanism { door: 3, .. })
    ));
}

#[test]
fn measurement_inline_pending_keeps_original_context_until_ticket_abandon() {
    let (d, p, host) = rig::<dispatch::kinds::secret::Secret>(secret, true);
    assert_eq!(
        crate::door_both_ways::open(&p, b"{}").outcome,
        Outcome::Ready
    );
    let ticket = d.inline_ticket().unwrap();
    let mode = 6;
    assert_eq!(
        with_context(Some(Arc::new(42u64)), || p.call_inline(
            ticket.ticket(),
            false,
            slot::TICK,
            &mut tick(&mode)
        ))
        .outcome,
        Outcome::Pending
    );
    let work = host.operations.lock().unwrap().last().unwrap().clone();
    assert_eq!(work.finished.load(Ordering::Acquire), 0);
    assert_eq!(
        with_context(Some(Arc::new("untrusted-context")), || p.call_inline(
            ticket.ticket(),
            true,
            slot::TICK,
            &mut tick(&mode)
        ))
        .outcome,
        Outcome::Pending
    );
    assert_eq!(
        work.captured
            .lock()
            .unwrap()
            .iter()
            .map(|batch| batch.revision)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    drop(ticket);
    assert_eq!(work.finished.load(Ordering::Acquire), 1);
    assert_eq!(crate::door_both_ways::close(&p).outcome, Outcome::Ready);
}

#[test]
fn measurement_host_maintenance_requires_empty_reports_even_on_declaring_plugins() {
    let (_d, p, host) = rig::<dispatch::kinds::secret::Secret>(secret, true);
    host.maintenance.store(true, Ordering::Release);
    assert_eq!(validate(&p, 8).outcome, Outcome::Ready);
    assert_eq!(validate(&p, 0).outcome, Outcome::Fault);
    assert!(host.operations.lock().unwrap().iter().all(|op| op
        .captured
        .lock()
        .unwrap()
        .is_empty()));
    assert!(dispatch::migrate::validate_migrated_door(
        dispatch::load::raw(secret),
        &serde_json::json!({})
    )
    .is_err());
}

#[test]
fn measurement_admission_checks_existing_and_new_bindings_including_empty_declarations() {
    struct Admission {
        seen: Mutex<Vec<Binding>>,
        reject_classes: bool,
    }
    impl Authority for Admission {
        fn admit(&self, binding: &Binding) -> Result<(), Refusal> {
            self.seen.lock().unwrap().push(binding.clone());
            if self.reject_classes && !binding.classes.is_empty() {
                Err(Refusal::Conflict)
            } else {
                Ok(())
            }
        }
        fn reserve(
            &self,
            _: &Binding,
            _: Option<&Context>,
            _: u32,
        ) -> Result<Arc<dyn Operation>, Refusal> {
            Err(Refusal::Unavailable)
        }
    }
    let (d, p, _) = rig::<dispatch::kinds::secret::Secret>(crate::neutral_secret::door, false);
    let authority = Arc::new(Admission {
        seen: Mutex::default(),
        reject_classes: true,
    });
    assert!(d.set_measurement_authority(authority.clone()).is_ok());
    assert!(authority.seen.lock().unwrap()[0].classes.is_empty());
    assert_eq!(d.measurement_bindings().len(), 1);
    let row = LinkedRow::of(secret).unwrap();
    let refused = dispatch::load_linked::<dispatch::kinds::secret::Secret>(
        &row,
        Bind {
            instance: "declaring".into(),
            max_inflight_cap: 1,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::Probe,
        },
    );
    assert!(matches!(refused, Err(dispatch::LoadError::BadStatement(_))));
    assert_eq!(d.measurement_bindings().len(), 1);
    assert_eq!(authority.seen.lock().unwrap().len(), 2);
    drop(p);
    assert!(d.measurement_bindings().is_empty());

    let (d, _p, _) = rig::<dispatch::kinds::secret::Secret>(secret, false);
    assert!(d
        .set_measurement_authority(Arc::new(Admission {
            seen: Mutex::default(),
            reject_classes: true
        }))
        .is_err());
    assert!(d
        .set_measurement_authority(Arc::new(Admission {
            seen: Mutex::default(),
            reject_classes: false
        }))
        .is_ok());
}

#[test]
fn measurement_autonomous_driver_has_explicit_system_attribution() {
    let (d, p, host) = rig::<dispatch::kinds::secret::Secret>(secret, true);
    assert_eq!(
        crate::door_both_ways::open(&p, b"{}").outcome,
        Outcome::Ready
    );
    *host.probe.lock().unwrap() = None;
    let driver = with_context(Some(Arc::new(42u64)), || d.driver(&p, 0)).unwrap();
    dispatch::ticket::Waking::of(p.inner.wake)
        .unwrap()
        .wake(driver);
    until(|| p.test_driver_answers() > 0);
    assert_eq!(host.contexts.lock().unwrap().last(), Some(&None));
    let work = host.operations.lock().unwrap().last().unwrap().clone();
    assert_eq!(work.captured.lock().unwrap().len(), 1);
    until(|| work.finished.load(Ordering::Acquire) == 1);
    d.recycle(driver);
    assert_eq!(crate::door_both_ways::close(&p).outcome, Outcome::Ready);
}

extern "C" fn continued_drive(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> RawOutcome {
    report(instance, input, output);
    // SAFETY: DRIVE carries the common initialized heads.
    let (input, output) = unsafe { (&*input.cast::<InHead>(), &mut *output.cast::<OutHead>()) };
    output.outcome = RawOutcome::of(if input.flags & FLAG_RESUME == 0 {
        Outcome::Pending
    } else {
        Outcome::Ready
    });
    output.outcome
}
extern "C" fn continued_driver() -> &'static Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    let address = *DOOR.get_or_init(|| {
        let mut parts = measured(crate::neutral_secret::door()).parts();
        // Preserve the complete kind-specific table while replacing its common DRIVE slot.
        let bytes = unsafe { (*parts.ops).size } as usize;
        let table = Box::leak(
            vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())].into_boxed_slice(),
        );
        unsafe {
            std::ptr::copy_nonoverlapping(
                parts.ops.cast::<u8>(),
                table.as_mut_ptr().cast::<u8>(),
                bytes,
            );
            let ops = table
                .as_mut_ptr()
                .cast::<busbar_contract::abi::mechanism::lifecycle::OpsHead>();
            (*ops).drive = Some(continued_drive);
            parts.ops = ops;
        }
        unsafe { Box::into_raw(Box::new(Door::__from_parts(parts))) as usize }
    });
    unsafe { &*(address as *const Door) }
}

#[test]
fn measurement_driver_continuation_keeps_parked_owner_then_returns_to_system() {
    let (d, p, host) = rig::<dispatch::kinds::secret::Secret>(continued_driver, true);
    assert_eq!(
        crate::door_both_ways::open(&p, b"{}").outcome,
        Outcome::Ready
    );
    *host.probe.lock().unwrap() = None;
    let driver = d.driver(&p, 0).unwrap();
    // Occupied exchanges park a submitted TICK until DRIVE drains their capacity.
    for caller in 0..p.inner.cap {
        d.services().held.inspection(driver, caller as usize, true);
    }
    let mode = 8;
    let reply = with_context(Some(Arc::new(42u64)), || {
        d.submit(
            &p,
            driver,
            slot::TICK,
            tick(&mode),
            busbar_contract::abi::mechanism::call::DeadlineClass::Call,
            0,
        )
    });
    until(|| d.is_pending(driver));
    let wake = dispatch::ticket::Waking::of(p.inner.wake).unwrap();
    wake.wake(driver);
    until(|| p.test_driver_answers() == 1);
    let operation = host.operations.lock().unwrap().last().unwrap().clone();
    assert_eq!(host.contexts.lock().unwrap().last(), Some(&Some(42)));
    // Resumption outside the submitting scope keeps the existing operation and cursor.
    wake.wake(driver);
    until(|| p.test_driver_answers() == 2);
    assert_eq!(
        reply.wait(Duration::from_secs(5)).unwrap().outcome,
        Outcome::Ready
    );
    assert_eq!(
        operation
            .captured
            .lock()
            .unwrap()
            .iter()
            .map(|b| b.revision)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    until(|| operation.finished.load(Ordering::Acquire) == 1);
    wake.wake(driver);
    until(|| p.test_driver_answers() == 3);
    assert_eq!(host.contexts.lock().unwrap().last(), Some(&None));
    wake.wake(driver);
    until(|| p.test_driver_answers() == 4);
    d.recycle(driver);
    assert_eq!(crate::door_both_ways::close(&p).outcome, Outcome::Ready);
}

fn plane_with_legacy_class(duplicate: bool) -> &'static Door {
    let mut parts = measured(crate::neutral_plane::door()).parts();
    // SAFETY: copy the neutral fixture's validated full plane tail into independent static data.
    let mut statement = unsafe { *parts.statement };
    let mut tail = unsafe {
        *statement
            .kind_tail
            .cast::<busbar_contract::abi::plane::PlaneTail>()
    };
    tail.billable_classes = Box::leak(Box::new(BillableClass {
        class: busbar_contract::abi::sdk::door::abi_str(if duplicate { "raw" } else { "legacy" }),
        family: busbar_contract::abi::sdk::door::abi_str("units"),
    }));
    tail.billable_classes_len = 1;
    statement.kind_tail = Box::into_raw(Box::new(tail)).cast();
    parts.statement = Box::leak(Box::new(statement));
    unsafe { Box::leak(Box::new(Door::__from_parts(parts))) }
}
extern "C" fn overlapping_plane() -> &'static Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    let pointer = *DOOR.get_or_init(|| plane_with_legacy_class(true) as *const Door as usize);
    unsafe { &*(pointer as *const Door) }
}
extern "C" fn disjoint_plane() -> &'static Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    let pointer = *DOOR.get_or_init(|| plane_with_legacy_class(false) as *const Door as usize);
    unsafe { &*(pointer as *const Door) }
}
#[test]
fn measurement_plane_common_and_legacy_class_ownership_must_be_disjoint() {
    let row = LinkedRow::of(overlapping_plane).unwrap();
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let result = dispatch::load_linked::<dispatch::kinds::plane::Plane>(
        &row,
        Bind {
            instance: "overlap".into(),
            max_inflight_cap: 1,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::Probe,
        },
    );
    assert!(
        matches!(result,Err(dispatch::LoadError::BadStatement(message)) if message.contains("'raw'") && message.contains("legacy plane"))
    );
    let (_d, p, _) = rig::<dispatch::kinds::plane::Plane>(disjoint_plane, true);
    assert_eq!(p.measurement_binding().classes[0].class, "raw");
    assert_eq!(
        p.context::<dispatch::kinds::plane::PlaneFacts>()
            .unwrap()
            .served
            .billable_classes,
        vec!["legacy"]
    );
    assert_eq!(validate(&p, 0).outcome, Outcome::Ready);
}
