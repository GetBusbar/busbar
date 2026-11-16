// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CHANNEL (ABI-MIN3-INTERFACE §14): Two sessions on one CARRIER_STDIO channel: one greet per
//! generation, CH_SERIAL ordering, replies demuxed to the right session; killing the child ends the
//! generation with P_ERROR and the next attach greets again.
//!
//! W1-K8A: the CH_SERIAL ordering arm runs on the channel's ask line (`channels::ask_line`, IF §12.19
//! round 18). The greet, demux and kill arms need the connector's stdio carrier (W1-C1C).

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

#[test]
#[ignore = "owner: W1-C1C; blocked (re-checked on dev 2026-11-16): the connector still drives framers over the old FramerDoor (OUTSTANDING row 6)"]
fn one_greet_per_generation_and_replies_demuxed_to_their_session() {
    todo!("owner: W1-C1C (C-CHANNEL greet/demux/kill arms: the connector's stdio carrier)")
}
