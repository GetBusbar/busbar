// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Existing adversarial ABI wake controls through the actual dispatcher, without a script formatter.
use crate::dispatch::{
    in_head, load_linked, now_ns, out_head, Bind, ConnTable, DispatchConfig, Dispatcher, Frame,
    LinkedRow, NoSink, NO_BLOB,
};
use crate::dispatch_test_plugin as plug;
use crate::dispatch_tests::TestKind;
use busbar_contract::abi::mechanism::call::{Blob, DeadlineClass, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{slot, TickIn, TickOut};
use std::sync::Arc;
use std::time::Duration;
#[test]
fn the_plane_host_dispatcher_reports_real_deadline_without_wake() {
    for missed_wake in [false, true] {
        let d = Dispatcher::new(DispatchConfig::default());
        let row = LinkedRow::of_raw(plug::busbar_plugin_door)
            .expect("existing adversarial ABI descriptor");
        let p = load_linked::<TestKind>(
            &row,
            Bind {
                instance: format!("plane-host-wake-{missed_wake}").into(),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: d.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .expect("bind existing raw wake boundary");
        let ticket = d.mint(0).expect("actual open ticket");
        let opened = d
            .submit(
                &p,
                ticket,
                slot::OPEN,
                crate::dispatch::lifecycle::open_frame(NO_BLOB),
                DeadlineClass::Call,
                0,
            )
            .wait(Duration::from_secs(10))
            .expect("open answers");
        d.recycle(ticket);
        assert_eq!(opened.outcome, Outcome::Ready);
        let mode = if missed_wake {
            plug::PEND_HOLD
        } else {
            plug::PEND_AFTER
        };
        let mut head = in_head();
        head.extensions = Blob {
            ptr: mode.as_ptr(),
            len: mode.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        let frame = Frame::new(
            TickIn {
                head,
                now_ns: now_ns(),
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 0,
            },
        );
        let ticket = d.mint(0).expect("actual tick ticket");
        let until = now_ns().saturating_add(if missed_wake {
            50_000_000
        } else {
            10_000_000_000
        });
        let answer = d
            .submit(&p, ticket, slot::TICK, frame, DeadlineClass::Call, until)
            .wait(Duration::from_secs(10))
            .expect("tick answers");
        d.recycle(ticket);
        if missed_wake {
            assert_ne!(answer.outcome, Outcome::Ready);
            assert_eq!(d.stats().deadline_without_wake, 1);
        } else {
            assert_eq!(answer.outcome, Outcome::Ready);
            assert_eq!(d.stats().deadline_without_wake, 0);
        }
    }
}
