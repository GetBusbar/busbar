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

#[tokio::test]
async fn every_framing_writes_directly_with_the_existing_wire_encoding() {
    use tokio::io::AsyncReadExt;
    for framing in [Framing::None, Framing::Ndjson, Framing::Sse] {
        let instance = ChannelBudget::new().instance();
        let bytes = b"one\ntwo\n";
        let message =
            GuardedWrite::new(&instance.unit(), &instance.link(), framing, bytes, false).unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(128);
        message.write(&mut writer).await.unwrap();
        drop(writer);
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, super::frame::frame(framing, bytes));
    }
}
