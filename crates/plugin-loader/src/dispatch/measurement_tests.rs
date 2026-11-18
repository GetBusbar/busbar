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
    lifecycle::{slot, ValidateIn},
};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Mutex, OnceLock,
};

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
fixture!(auth, crate::neutral_auth::door);
fixture!(hook, crate::hook_door_plugin::conforming::door);
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
            accept: Default::default(),
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
fn common_measurement_crosses_every_door_kind_identity_and_copies_ffi_storage() {
    use dispatch::kinds::*;
    crosses::<auth::Auth>(auth);
    crosses::<hook::Hook>(hook);
    crosses::<export::Export>(export);
    crosses::<plane::Plane>(plane);
    crosses::<transport::Transport>(transport);
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
            accept: Default::default(),
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
