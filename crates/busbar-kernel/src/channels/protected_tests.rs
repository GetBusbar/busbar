// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::budget::*;
use super::protected::*;

#[test]
fn general_reclassification_keeps_the_fixed_backing_charged() {
    let process = ChannelBudget::new();
    let unit = process.instance().unit();
    let mut inspection = ReplyStorage::new(&unit).unwrap();
    inspection.output_mut()[0] = 42;
    let general = inspection.into_general().unwrap();
    assert_eq!(general.output()[0], 42);
    assert_eq!(unit.used().bytes, OUTPUT_BYTES);
    assert_eq!(unit.used().completions, 1);
    // Returning unused staging entitlement permits another protected entry, but keeps the
    // original general backing charged until its actual owner retires.
    let second = ReplyStorage::new(&unit).unwrap();
    assert_eq!(unit.used().bytes, OUTPUT_BYTES + REPLY_BYTES);
    drop((general, second));
    assert_eq!(process.used(), Claim::default());
}

#[test]
fn saturated_general_reclassification_discards_the_whole_answer() {
    let process = ChannelBudget::new();
    let unit = process.instance().unit();
    let full = unit
        .reserve(
            Claim {
                bytes: UNIT_BYTES - REPLY_BYTES,
                ..Claim::default()
            },
            None,
        )
        .unwrap();
    assert!(ReplyStorage::new(&unit).unwrap().into_general().is_err());
    assert_eq!(unit.used().bytes, UNIT_BYTES - REPLY_BYTES);
    assert_eq!(unit.used().completions, 0);
    drop(full);
    assert_eq!(process.used(), Claim::default());
}

#[tokio::test]
async fn reply_backing_moves_to_writer_and_stays_charged_through_flush() {
    use tokio::io::AsyncReadExt;
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let link = instance.link();
    let general = unit
        .reserve(
            Claim {
                bytes: UNIT_BYTES - REPLY_BYTES,
                ..Claim::default()
            },
            None,
        )
        .unwrap();
    let mut inspection = ReplyStorage::new(&unit).unwrap();
    inspection.output_mut()[24..29].copy_from_slice(b"reply");
    let write = inspection.into_write(24..29, &link).unwrap();
    assert_eq!(unit.used().bytes, UNIT_BYTES - REPLY_BYTES + 6);
    let (mut sender, mut reader) = tokio::io::duplex(2);
    let run = tokio::spawn(async move { write.write_ndjson(&mut sender).await });
    tokio::task::yield_now().await;
    assert_eq!(unit.used().messages, 1, "the blocked writer owns its cell");
    let mut bytes = [0; 6];
    reader.read_exact(&mut bytes).await.unwrap();
    run.await.unwrap().unwrap();
    assert_eq!(&bytes, b"reply\n");
    drop(general);
    assert_eq!(process.used(), Claim::default());
}

#[test]
fn invalid_reply_range_and_foreign_destination_publish_nothing() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let other = process.instance().link();
    let inspection = ReplyStorage::new(&unit).unwrap();
    assert!(inspection.into_write(0..1, &other).is_err());
    assert_eq!(process.used(), Claim::default());
    let inspection = ReplyStorage::new(&unit).unwrap();
    assert!(inspection
        .into_write(0..OUTPUT_BYTES + 1, &instance.link())
        .is_err());
    assert_eq!(process.used(), Claim::default());
}

#[test]
fn maximum_reply_fits_reserved_native_envelope_at_general_saturation() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let general = unit
        .reserve(
            Claim {
                bytes: UNIT_BYTES - REPLY_BYTES,
                ..Claim::default()
            },
            None,
        )
        .unwrap();
    let inspection = ReplyStorage::new(&unit).unwrap();
    assert_eq!(inspection.output().len(), OUTPUT_BYTES);
    let writer = inspection
        .into_write(24..OUTPUT_BYTES, &instance.link())
        .unwrap();
    assert_eq!(writer.len(), super::frame::MAX_MESSAGE);
    assert!(
        ReplyStorage::new(&unit).is_err(),
        "queued reply retains the protected bytes"
    );
    drop((writer, general));
    assert_eq!(process.used(), Claim::default());
}

#[tokio::test]
async fn canceled_blocked_writer_releases_its_real_payload_and_cell() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let inspection = ReplyStorage::new(&unit).unwrap();
    let writer = inspection
        .into_write(24..OUTPUT_BYTES, &instance.link())
        .unwrap();
    let (mut sender, _reader) = tokio::io::duplex(1);
    let run = tokio::spawn(async move { writer.write_ndjson(&mut sender).await });
    tokio::task::yield_now().await;
    drop(unit);
    assert_eq!(process.used().messages, 1);
    run.abort();
    assert!(run.await.unwrap_err().is_cancelled());
    assert_eq!(process.used(), Claim::default());
}
