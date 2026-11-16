// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CHANNEL (ABI-MIN3-INTERFACE §14): Two sessions on one CARRIER_STDIO channel: one greet per
//! generation, CH_SERIAL ordering, replies demuxed to the right session; killing the child ends the
//! generation with P_ERROR and the next attach greets again.
//!
//! W1-K8A: the CH_SERIAL ordering arm runs on the channel's ask line (`channels::ask_line`, IF §12.19
//! round 18). The greet, demux and kill arms are relocated into busbar-kernel (re-checked 2026-11-16: the
//! channel carrier is the kernel's, not the connector's, so no W1-C1C piece is missing). TEST-VALUE pointers, each
//! clause of the case text:
//!
//! - one greet per generation, the next session waits for CH_READY, a leaving greeter hands the greeting on:
//!   `channels::carrier_tests::the_first_attach_of_a_generation_greets_and_the_next_waits_for_its_ready` and
//!   `a_greeter_that_leaves_without_ready_hands_the_greeting_to_the_next`
//!   (crates/busbar-kernel/src/channels/carrier_tests.rs:284, :312);
//! - CH_SERIAL ordering and replies demuxed to their own session by slot:
//!   `messages_are_written_framed_and_a_final_reply_releases_the_next_serial_ask` (carrier_tests.rs:326) and the
//!   live arm below;
//! - killing the child ends the generation for every session, the next attach greets again as generation 2:
//!   `a_child_that_exits_ends_the_generation_for_every_session_and_the_next_attach_respawns_after_100_ms`
//!   (carrier_tests.rs:466);
//! - the ended generation reaches the plane as P_ERROR on that exchange and the channel is let go:
//!   `plane_driver::tests::port_carrier_tests::a_channel_that_ends_is_a_p_error_on_its_exchange_and_the_channel_is_let_go`
//!   (crates/busbar-kernel/src/plane_driver/tests/port_carrier_tests.rs:551).

use busbar_kernel::channels::ask_line::{AskLine, Write};

#[test]
fn two_sessions_on_one_serial_channel_are_written_in_turn() {
    let mut line = AskLine::new(true);
    assert_eq!(
        line.send(1, b"ask-1", true),
        Write::Now(Box::from(&b"ask-1"[..]))
    );
    assert_eq!(
        line.send(2, b"ask-2", true),
        Write::Queued,
        "CH_SERIAL: one outstanding ask"
    );
    assert_eq!(line.head(), Some(1));
    assert_eq!(
        line.finished(1),
        vec![Box::<[u8]>::from(&b"ask-2"[..])],
        "DX_FINAL hands the line on"
    );
    assert_eq!(line.head(), Some(2));
    assert_eq!(
        line.ended(),
        vec![2],
        "a dead child ends the generation: the open ask gets P_ERROR"
    );
}
