// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One op, one connection: a store op's checkout answers its own stream again for the same need
//! and target, and is REFUSED for any other; an op on no ticket may not pend.

use std::task::Poll;

use super::{Checkout, Op, Parked};
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::sdk::conn::ConnFailure;

const TICKET: Ticket = Ticket {
    slot: 3,
    generation: 1,
};

fn holding(need: u32, target: Option<&str>) -> Op<'static> {
    Op::enter(
        TICKET,
        None,
        Some(Parked {
            state: None,
            checkout: Some(Checkout {
                need,
                target: target.map(str::to_owned),
                stream: 42,
            }),
            issued: 1,
            host: None,
            ticket: TICKET,
        }),
    )
}

#[test]
fn a_second_checkout_for_the_same_need_and_target_is_the_same_stream() {
    let mut op = holding(0, Some("db:5432"));
    assert_eq!(op.checkout(0, Some("db:5432")), Poll::Ready(Ok(42)));
}

#[test]
fn a_second_checkout_for_another_target_or_need_is_refused() {
    let mut op = holding(0, Some("db:5432"));
    assert!(matches!(
        op.checkout(0, Some("other:5432")),
        Poll::Ready(Err(ConnFailure::Refused(_)))
    ));
    assert!(matches!(
        op.checkout(1, Some("db:5432")),
        Poll::Ready(Err(ConnFailure::Refused(_)))
    ));
}

#[test]
fn an_op_on_no_ticket_may_not_pend_or_connect() {
    let mut op = Op::detached();
    assert!(!op.can_pend());
    op.park(7u32);
    assert_eq!(op.resume::<u32>(), None, "nothing is kept on no ticket");
    assert!(matches!(op.connector(), Err(ConnFailure::Unarmed)));
}
