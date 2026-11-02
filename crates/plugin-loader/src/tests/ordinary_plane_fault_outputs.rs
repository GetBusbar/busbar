// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Malicious output boundaries on the retained actual MCP descriptor, without text judges.
use crate::dispatch::kinds::plane::{open_door, Plane};
use crate::dispatch::{
    in_head, load_linked, out_head, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, LinkedRow,
    NoSink,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::plane::{slot, ArriveIn, ArriveOut, Ops, ProjectIn, ProjectOut};
use std::sync::{Arc, OnceLock};
static DESCRIPTOR: OnceLock<usize> = OnceLock::new();
const UNJUDGED: &[u8] = b"unjudged";
fn blank<T>() -> T {
    // SAFETY: used only with plain ABI integer/pointer frames.
    unsafe { std::mem::zeroed() }
}
extern "C" fn fault_arrive(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    // SAFETY: caller owns an initialized exclusive ArriveOut; sentinel is process-static.
    unsafe {
        let o = &mut *out.cast::<ArriveOut>();
        o.pool = AbiStr::over(UNJUDGED);
        o.head.error = AbiStr::over(UNJUDGED);
        o.head.outcome = RawOutcome::of(Outcome::Fault);
    }
    RawOutcome::of(Outcome::Fault)
}
extern "C" fn fault_project(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    // SAFETY: caller owns an initialized exclusive ProjectOut; no prompt payload is initialized.
    unsafe {
        let o = &mut *out.cast::<ProjectOut>();
        o.prompt.messages_len = usize::MAX as _;
        o.head.error = AbiStr::over(UNJUDGED);
        o.head.outcome = RawOutcome::of(Outcome::Fault);
    }
    RawOutcome::of(Outcome::Fault)
}
extern "C" fn fault_door() -> &'static Door {
    let at = *DESCRIPTOR.get_or_init(|| {
        let real = *crate::actual_mcp::door();
        // SAFETY: actual SDK-built retained MCP table, replacing only adversarial raw output slots.
        let ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
        let ops = Box::leak(Box::new(Ops {
            arrive: Some(fault_arrive),
            project: Some(fault_project),
            ..ops
        }));
        let d = unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..real.parts()
            })
        };
        Box::into_raw(Box::new(d)) as usize
    });
    // SAFETY: boxed descriptor and actual MCP image remain alive for this process.
    unsafe { &*(at as *const Door) }
}
#[test]
fn fault_arrival_and_projection_never_copy_unjudged_output_text() {
    for project in [false, true] {
        let d = Dispatcher::new(DispatchConfig::default());
        let p = load_linked::<Plane>(
            &LinkedRow::of(fault_door).unwrap(),
            Bind {
                instance: format!("unjudged-{project}").into(),
                max_inflight_cap: 8,
                sink: Arc::new(NoSink),
                dispatcher: d.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .unwrap();
        open_door(&p, b"{}", b"{}", None).expect("actual MCP opens");
        let answer = if project {
            let mut i: ProjectIn = blank();
            i.head = in_head();
            i.unit = 1;
            let mut o: ProjectOut = blank();
            o.head = out_head();
            p.call(slot::PROJECT, &mut Frame::new(i, o))
        } else {
            let mut i: ArriveIn = blank();
            i.head = in_head();
            i.unit = 1;
            let mut o: ArriveOut = blank();
            o.head = out_head();
            p.call(slot::ARRIVE, &mut Frame::new(i, o))
        };
        assert_eq!(answer.outcome, Outcome::Fault);
        assert!(
            answer.error.is_none(),
            "Fault must never copy the unjudged error/payload"
        );
        assert_eq!(answer.lease, 0);
    }
}
