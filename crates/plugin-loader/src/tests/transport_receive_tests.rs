// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::dispatch::framing_context::{self, FramingContext};
use busbar_contract::abi::mechanism::call::OutHead;
use busbar_contract::abi::mechanism::lifecycle::ReleaseIn;
use busbar_contract::abi::transport::{slot, FramerOut, IngestIn};
use busbar_contract::framing_scope::FramingScope;

#[test]
fn retained_input_is_copied_on_pending_and_ready_only_to_the_current_leg() {
    use crate::dispatch::kinds::transport::Transport;
    use crate::dispatch::{load_linked, LinkedRow};
    let row = LinkedRow::of_raw(crate::conformance::transport_receive_fixture::door).unwrap();
    let plugin = load_linked::<Transport>(&row, bind()).unwrap();
    let mut open = Frame::new(blank_in::<OpenIn>(), blank_out::<OpenOut>());
    assert_eq!(plugin.call(life::OPEN, &mut open).outcome, Outcome::Ready);
    let a = FramingContext::new(plugin.instance().0, 0, 0, None).unwrap();
    let b = FramingContext::new(plugin.instance().0, 0, a.connection(), None).unwrap();
    assert_ne!(a.leg(), b.leg());
    let ticket = busbar_contract::abi::mechanism::ticket::Ticket {
        slot: 13,
        generation: 17,
    };
    let crossing = |scope: Arc<FramingContext>, n: usize| {
        let input_bytes = vec![0; n];
        let mut input: IngestIn = blank_in();
        input.head = in_head();
        input.head.ticket = ticket;
        input.bytes = input_bytes.as_ptr();
        input.len = n;
        let mut output: FramerOut = blank_out();
        output.head = out_head();
        let mut frame = Frame::new(input, output);
        let erased: Arc<dyn FramingScope> = scope;
        let called = framing_context::with_context(Some(erased), || {
            plugin.call_inline(ticket, false, slot::INGEST, &mut frame)
        });
        if called.lease != 0 {
            let mut input: ReleaseIn = blank_in();
            input.lease = called.lease;
            let mut frame = Frame::new(input, blank_out::<OutHead>());
            assert_eq!(
                plugin.call(life::RELEASE, &mut frame).outcome,
                Outcome::Ready
            );
        }
        called.outcome
    };
    assert_eq!(crossing(a.clone(), 7), Outcome::Pending);
    assert_eq!(
        a.retained_input(),
        7,
        "the leased bytes were copied before release"
    );
    assert_eq!(
        b.retained_input(),
        0,
        "a second leg shares no accounting state"
    );
    assert_eq!(crossing(b.clone(), 3), Outcome::Ready);
    assert_eq!((a.retained_input(), b.retained_input()), (7, 3));
    assert_eq!(crossing(a.clone(), 0), Outcome::Ready);
    assert_eq!((a.retained_input(), b.retained_input()), (0, 3));
    assert_eq!(
        crossing(b.clone(), 9),
        Outcome::Fault,
        "a present non-u64 report is refused"
    );
    assert_eq!(
        b.retained_input(),
        3,
        "malformed reports cannot clear existing pressure"
    );
}
