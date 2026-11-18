// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::budget::{ChannelBudget, Claim, REPLY_BYTES, UNIT_BYTES};
use super::frame::Framing;
use super::link::Link;
use super::protected::{GuardedWrite, ReplyStorage};

#[tokio::test]
async fn saturated_general_capacity_still_enqueues_one_owned_reply() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let budget = instance.link();
    let (link, mut queue) = Link::new(false, Framing::Ndjson, budget.clone());
    assert!(link.attach(1));
    let general = unit
        .reserve(
            Claim {
                bytes: UNIT_BYTES - REPLY_BYTES,
                ..Claim::default()
            },
            None,
        )
        .unwrap();
    let mut storage = ReplyStorage::new(&unit).unwrap();
    storage.output_mut()[24..29].copy_from_slice(b"reply");
    let message = storage.into_write(24..29, &budget).unwrap();
    let address = message.as_bytes().as_ptr();
    link.send_owned(1, message).unwrap();
    let queued = queue.recv().await.unwrap();
    assert_eq!(
        queued.as_bytes().as_ptr(),
        address,
        "the queue moves the allocation"
    );
    assert_eq!(unit.used().messages, 1);
    drop(queued);
    drop(general);
    assert_eq!(process.used(), Claim::default());
}

#[test]
fn general_messages_leave_the_actual_writer_cell_for_a_protected_reply() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let budget = instance.link();
    let (link, queue) = Link::new(false, Framing::Ndjson, budget.clone());
    assert!(link.attach(1));
    for _ in 0..63 {
        link.send_owned(
            1,
            GuardedWrite::new(&unit, &budget, Framing::Ndjson, b"x", false).unwrap(),
        )
        .unwrap();
    }
    assert!(GuardedWrite::new(&unit, &budget, Framing::Ndjson, b"x", false).is_err());
    let storage = ReplyStorage::new(&unit).unwrap();
    link.send_owned(1, storage.into_write(24..25, &budget).unwrap())
        .unwrap();
    assert_eq!(unit.used().messages, 64);
    drop(queue);
    assert_eq!(process.used(), Claim::default());
}

#[tokio::test]
async fn serial_asks_retain_metadata_and_move_waiting_payload_only_once() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let budget = instance.link();
    let (link, mut queue) = Link::new(true, Framing::Ndjson, budget.clone());
    assert!(link.attach(1));
    assert!(link.attach(2));
    for (slot, bytes) in [(1, b"first".as_slice()), (2, b"second".as_slice())] {
        link.send_owned(
            slot,
            GuardedWrite::new(&unit, &budget, Framing::Ndjson, bytes, true).unwrap(),
        )
        .unwrap();
    }
    drop(queue.recv().await.unwrap());
    assert_eq!(
        unit.used().asks,
        2,
        "write completion does not finish an ask"
    );
    assert_eq!(
        unit.used().messages,
        1,
        "only the waiting ask retains a payload"
    );
    assert!(queue.try_recv().is_err());
    link.finished(1);
    assert_eq!(unit.used().asks, 1);
    let next = queue.recv().await.unwrap();
    assert_eq!(next.as_bytes(), b"second");
    link.finished(1); // duplicate/late final cannot publish the next ask twice
    assert!(queue.try_recv().is_err());
    drop(next);
    link.finished(2);
    assert_eq!(process.used(), Claim::default());
}

#[test]
fn foreign_destination_and_ended_generation_drop_without_publication() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let budget = instance.link();
    let (link, mut queue) = Link::new(false, Framing::Ndjson, budget.clone());
    assert!(link.attach(1));
    let foreign =
        GuardedWrite::new(&unit, &instance.link(), Framing::Ndjson, b"foreign", false).unwrap();
    assert!(link.send_owned(1, foreign).is_err());
    assert!(queue.try_recv().is_err());
    link.ended();
    let late = GuardedWrite::new(&unit, &budget, Framing::Ndjson, b"late", false).unwrap();
    assert!(link.send_owned(1, late).is_err());
    assert_eq!(process.used(), Claim::default());
}

#[test]
fn sessionless_fallback_uses_only_real_instance_general_capacity() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let budget = instance.link();
    let mut held = Vec::new();
    let mut left = (64 << 20) - REPLY_BYTES;
    while left != 0 {
        let unit = instance.unit();
        let bytes = left.min(UNIT_BYTES - REPLY_BYTES);
        held.push(
            unit.reserve(
                Claim {
                    bytes,
                    ..Claim::default()
                },
                None,
            )
            .unwrap(),
        );
        left -= bytes;
    }
    assert!(GuardedWrite::fallback(&instance, &budget, Framing::Ndjson, b"refusal").is_err());
    assert_eq!(process.used().messages, 0);
    drop(held);
    let write = GuardedWrite::fallback(&instance, &budget, Framing::Ndjson, b"refusal").unwrap();
    assert_eq!(process.used().messages, 1);
    drop(write);
    assert!(GuardedWrite::fallback(&instance, &budget, Framing::Ndjson, &[0; 4097]).is_err());
    assert_eq!(process.used(), Claim::default());
}

#[test]
fn ordinary_data_cannot_bypass_its_saturated_unit() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let budget = instance.link();
    let full = unit
        .reserve(
            Claim {
                bytes: UNIT_BYTES - REPLY_BYTES,
                ..Claim::default()
            },
            None,
        )
        .unwrap();
    assert!(GuardedWrite::new(&unit, &budget, Framing::Ndjson, b"data", false).is_err());
    assert_eq!(unit.used().messages, 0);
    // Only the private, validated, sessionless fallback may use its channel's general owner.
    let fallback = GuardedWrite::fallback(&instance, &budget, Framing::Ndjson, b"refusal").unwrap();
    assert_eq!(unit.used().messages, 0);
    drop((full, fallback));
    assert_eq!(process.used(), Claim::default());
}

/// What `message` puts on the wire under `framing`, written by the production writer.
async fn written(framing: Framing, message: &[u8]) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let instance = ChannelBudget::new().instance();
    let message =
        GuardedWrite::new(&instance.unit(), &instance.link(), framing, message, false).unwrap();
    let (mut writer, mut reader) = tokio::io::duplex(128);
    message.write(&mut writer).await.unwrap();
    drop(writer);
    let mut actual = Vec::new();
    reader.read_to_end(&mut actual).await.unwrap();
    actual
}

#[tokio::test]
async fn every_framing_writes_directly_with_the_existing_wire_encoding() {
    // No framing: the message as it is, line breaks included.
    assert_eq!(
        written(Framing::None, b"one\ntwo\r\n").await,
        b"one\ntwo\r\n"
    );
    // Newline-delimited: the message and one `\n`; an empty message is a blank line.
    assert_eq!(
        written(Framing::Ndjson, b"{\"id\":1}").await,
        b"{\"id\":1}\n"
    );
    assert_eq!(written(Framing::Ndjson, b"").await, b"\n");
    // SSE: each `\n` starts another `data:` line, a blank line ends the event, and it reads back whole.
    let sse = written(Framing::Sse, b"one\ntwo").await;
    assert_eq!(sse, b"data: one\ndata: two\n\n");
    let mut back = super::frame::Framer::new(
        Framing::Sse,
        ChannelBudget::new().instance().unit().storage(),
    )
    .unwrap();
    let messages = back.push(&sse).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].as_ref(), b"one\ntwo");
}

/// Messages a newline-delimited reader would take for more than one line: a line feed in the middle (the old
/// stdio plugin's `two\nlines`), a trailing line feed, a carriage return in the middle (a reader that ends a line
/// on a lone `\r`), and a trailing carriage return (the old plugin's `a return\r`).
const NOT_ONE_LINE: [&[u8]; 4] = [b"two\nlines", b"a line\n", b"a\rreturn", b"a return\r"];

#[test]
fn an_ordinary_send_holding_a_line_break_is_refused_before_it_is_charged() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let budget = instance.link();
    for message in NOT_ONE_LINE {
        for ask in [false, true] {
            assert!(
                GuardedWrite::new(&unit, &budget, Framing::Ndjson, message, ask).is_err(),
                "{message:?} (ask {ask}) is not one line"
            );
            assert_eq!(
                process.used(),
                Claim::default(),
                "{message:?} charged nothing"
            );
        }
    }
}

#[test]
fn a_fallback_holding_a_line_break_is_refused_before_it_is_charged() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let budget = instance.link();
    for message in NOT_ONE_LINE {
        assert!(
            GuardedWrite::fallback(&instance, &budget, Framing::Ndjson, message).is_err(),
            "{message:?} is not one line"
        );
        assert_eq!(
            process.used(),
            Claim::default(),
            "{message:?} charged nothing"
        );
    }
}

#[test]
fn a_protected_reply_holding_a_line_break_is_refused_before_it_is_charged() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let budget = instance.link();
    for message in NOT_ONE_LINE {
        let mut storage = ReplyStorage::new(&unit).unwrap();
        let end = 24 + message.len();
        storage.output_mut()[24..end].copy_from_slice(message);
        assert!(
            storage.into_write(24..end, &budget).is_err(),
            "{message:?} is not one line"
        );
        assert_eq!(
            process.used(),
            Claim::default(),
            "{message:?} charged nothing"
        );
    }
}

#[test]
fn an_sse_message_holding_a_carriage_return_is_refused() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let budget = instance.link();
    for message in [b"a\rreturn".as_slice(), b"a return\r", b"\r\n"] {
        assert!(
            GuardedWrite::new(&unit, &budget, Framing::Sse, message, false).is_err(),
            "{message:?} would end an SSE field"
        );
        assert!(
            GuardedWrite::fallback(&instance, &budget, Framing::Sse, message).is_err(),
            "{message:?} would end an SSE field"
        );
        assert_eq!(process.used(), Claim::default());
    }
    // A line feed is not refused under SSE: the writer makes it its own `data:` line.
    assert!(GuardedWrite::new(&unit, &budget, Framing::Sse, b"one\ntwo", false).is_ok());
}

#[tokio::test]
async fn a_plane_send_holding_a_line_break_is_invalid_and_the_next_message_goes_out_alone() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let (link, mut queue) = Link::new(true, Framing::Ndjson, instance.link());
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let mut attachment =
        super::Attachment::linked(link, unit, 1, 1, false, Default::default(), rx).unwrap();
    for message in NOT_ONE_LINE {
        assert_eq!(
            attachment.send(message, true).await,
            Err(crate::plugin_records::RecordsDenied::Invalid),
            "{message:?} is refused as invalid, not as a channel that is gone"
        );
        assert!(queue.try_recv().is_err(), "{message:?} queued nothing");
    }
    attachment.send(b"{\"id\":1}", true).await.unwrap();
    let next = queue.recv().await.unwrap();
    assert_eq!(next.as_bytes(), b"{\"id\":1}");
    assert!(queue.try_recv().is_err());
}

#[tokio::test]
async fn detach_discards_a_queued_write_that_has_not_started() {
    use tokio::io::AsyncReadExt;
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let budget = instance.link();
    let (link, mut queue) = Link::new(false, Framing::Ndjson, budget.clone());
    assert!(link.attach(1));
    link.send_owned(
        1,
        GuardedWrite::new(&unit, &budget, Framing::Ndjson, b"canceled", false).unwrap(),
    )
    .unwrap();
    link.detach(1, false);
    let (mut writer, mut reader) = tokio::io::duplex(32);
    queue
        .recv()
        .await
        .unwrap()
        .write(&mut writer)
        .await
        .unwrap();
    drop(writer);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty());
    assert_eq!(process.used(), Claim::default());
}

#[tokio::test]
async fn detach_does_not_release_or_replay_an_already_started_write() {
    use tokio::io::AsyncReadExt;
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let budget = instance.link();
    let (link, mut queue) = Link::new(false, Framing::Ndjson, budget.clone());
    assert!(link.attach(1));
    link.send_owned(
        1,
        GuardedWrite::new(&unit, &budget, Framing::Ndjson, b"started", false).unwrap(),
    )
    .unwrap();
    let message = queue.recv().await.unwrap();
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let run = tokio::spawn(async move { message.write(&mut writer).await });
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes[..1]).await.unwrap();
    link.detach(1, false);
    assert_eq!(unit.used().messages, 1);
    reader.read_exact(&mut bytes[1..]).await.unwrap();
    run.await.unwrap().unwrap();
    assert_eq!(&bytes, b"started\n");
    assert_eq!(process.used(), Claim::default());
}
