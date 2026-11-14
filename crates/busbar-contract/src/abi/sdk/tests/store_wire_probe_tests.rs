// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The wire's own probes (the bound's clock read, a retry's wake, closing the op's checkout) never
//! make a `NoTicket` on a ticketless op: nothing hands it to plugin code, so it must not count as
//! the op being refused a pend (LINT-RULES R28 `ready-after-no-ticket`). A `NoTicket` the wire does
//! hand the body still counts.

use super::{drive, Host, Wire};
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::sdk::conn::ConnFailure;
use crate::abi::sdk::door::take_no_ticket;
use crate::abi::sdk::store::{Op, Step};

/// `body` driven on a ticketless op over the empty host: its answer, and whether the SDK made a
/// `NoTicket` while it ran.
fn ticketless(
    body: fn(Wire) -> super::Body<Result<(), ConnFailure>>,
) -> (Step<Result<(), ConnFailure>>, bool) {
    let host = Host::NONE;
    take_no_ticket();
    let mut op = Op::enter(Ticket::NONE, Some(&host), None, None);
    let answer = drive(&mut op, body);
    drop(op);
    (answer, take_no_ticket())
}

#[test]
fn a_bounded_ticketless_op_with_no_wire_io_makes_no_no_ticket() {
    let (answer, handed) = ticketless(|wire| {
        Box::pin(async move {
            wire.bound(5);
            wire.close().await;
            Ok(())
        })
    });
    assert_eq!(answer, Step::Ready(Ok(())));
    assert!(
        !handed,
        "the bound's clock probe made a NoTicket nothing was handed"
    );
}

#[test]
fn a_no_ticket_the_wire_hands_the_body_still_counts() {
    let (answer, handed) = ticketless(|wire| Box::pin(async move { wire.wait_codec().await }));
    assert_eq!(answer, Step::Ready(Err(ConnFailure::NoTicket)));
    assert!(handed, "the body was handed NoTicket");
}
