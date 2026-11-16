// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-EXPORT-DELIVERY (ABI-MIN3-INTERFACE §14): The export chunk contract (round 33).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! W1-A9 owns arms (a) and (b): the record layout and constants, and the describe rules of `decode_delivery`.

use busbar_plugin_abi::kinds::export::export::{
    tag, CustodyRec, DeliveryRec, ALL, CUSTODY_ACCEPTED, CUSTODY_DURABLE, CUSTODY_INDEXED,
    CUSTODY_NONE, M_CONFIRM, M_DELIVER, M_RENDER, STREAM_CONTENT, STREAM_COUNT,
};
use busbar_plugin_abi::records::{tag as generic, Records, Reply, Writer};
use busbar_plugin_loader::encode::export::decode_delivery;

#[test]
fn custody_and_delivery_records() {
    // (a) CustodyRec and DeliveryRec are 8 bytes with no padding.
    assert_eq!(core::mem::size_of::<CustodyRec>(), 8);
    assert_eq!(core::mem::offset_of!(CustodyRec, level), 0);
    assert_eq!(core::mem::offset_of!(CustodyRec, recheck_s), 4);
    assert_eq!(core::mem::size_of::<DeliveryRec>(), 8);
    assert_eq!(core::mem::offset_of!(DeliveryRec, pending_capacity), 0);
    // CUSTODY is 0x0104 and D_DELIVERY 0x0183.
    assert_eq!(tag::CUSTODY, 0x0104);
    assert_eq!(tag::D_DELIVERY, 0x0183);
    // M_DELIVER and M_RENDER keep bits 0 and 1; M_CONFIRM is 1 << 2.
    assert_eq!(M_DELIVER, 1 << 0);
    assert_eq!(M_RENDER, 1 << 1);
    assert_eq!(M_CONFIRM, 1 << 2);
    assert_eq!(ALL, M_DELIVER | M_RENDER | M_CONFIRM);
    // STREAM_CONTENT is 9 and STREAM_COUNT 10.
    assert_eq!(STREAM_CONTENT, 9);
    assert_eq!(STREAM_COUNT, 10);
    // The custody levels ascend from NONE.
    assert_eq!(
        [
            CUSTODY_NONE,
            CUSTODY_ACCEPTED,
            CUSTODY_DURABLE,
            CUSTODY_INDEXED
        ],
        [0, 1, 2, 3]
    );
}

/// One describe answer: D_STREAMS (one `u8` id per byte), then the optional items.
fn describe(streams: &[u8], delivery: &[u64], dest_path: bool) -> Reply {
    let mut w = Reply::new();
    w.put(tag::D_STREAMS, streams).unwrap();
    for capacity in delivery {
        w.put(tag::D_DELIVERY, &capacity.to_le_bytes()).unwrap();
    }
    if dest_path {
        w.put_text(generic::D_DEST_PATH, "/dest").unwrap();
    }
    w
}

#[test]
fn confirm_and_delivery_describe_rules() {
    let content = [0u8, 1, 9];
    let no_content = [0u8, 1];
    let run = |w: &Reply, methods: u64| decode_delivery(Records::new(w.as_bytes()), methods);

    // The valid shape: M_CONFIRM with one D_DELIVERY, STREAM_CONTENT declared and no D_DEST_PATH.
    assert_eq!(
        run(&describe(&content, &[4], false), M_DELIVER | M_CONFIRM).unwrap(),
        Some(4)
    );
    // Neither declared: no pending capacity.
    assert_eq!(
        run(&describe(&no_content, &[], false), M_DELIVER).unwrap(),
        None
    );
    // M_CONFIRM without D_DELIVERY.
    assert!(run(&describe(&content, &[], false), M_DELIVER | M_CONFIRM).is_err());
    // D_DELIVERY without M_CONFIRM.
    assert!(run(&describe(&content, &[4], false), M_DELIVER).is_err());
    // pending_capacity 0.
    assert!(run(&describe(&content, &[0], false), M_DELIVER | M_CONFIRM).is_err());
    // Two D_DELIVERY.
    assert!(run(&describe(&content, &[4, 4], false), M_DELIVER | M_CONFIRM).is_err());
    // M_CONFIRM without STREAM_CONTENT.
    assert!(run(&describe(&no_content, &[4], false), M_DELIVER | M_CONFIRM).is_err());
    // M_CONFIRM with D_DEST_PATH.
    assert!(run(&describe(&content, &[4], true), M_DELIVER | M_CONFIRM).is_err());
    // A D_DELIVERY body that is not a DeliveryRec.
    let mut short = Reply::new();
    short.put(tag::D_STREAMS, &content).unwrap();
    short.put(tag::D_DELIVERY, &[1, 0, 0, 0]).unwrap();
    assert!(run(&short, M_DELIVER | M_CONFIRM).is_err());
}

/// (c) L7's half that needs no live image: how a decoded `deliver` answer becomes the port's `Delivered`. The
/// CUSTODY grammar FAULTs and the `open` ceiling grammar are `encode::export`'s own unit tests; the same grammar
/// through a running proxy waits on a kind-level export double.
#[test]
fn custody_answer_rules() {
    use busbar_plugin_loader::adapters::export::delivered_from;
    use busbar_plugin_loader::ports::export::{Custody, Delivered};

    // No CUSTODY reads ACCEPTED with no recheck.
    match delivered_from(3, None, None, 0).unwrap() {
        Delivered::Acked { accepted, custody } => {
            assert_eq!(accepted, 3);
            assert_eq!(
                custody,
                Custody {
                    level: CUSTODY_ACCEPTED,
                    recheck_s: 0
                }
            );
        }
        other => panic!("{other:?}"),
    }
    // A stated CUSTODY is passed through, recheck included.
    let stated = CustodyRec {
        level: CUSTODY_DURABLE,
        recheck_s: 30,
    };
    match delivered_from(2, None, Some(stated), 0).unwrap() {
        Delivered::Acked { custody, .. } => assert_eq!(
            custody,
            Custody {
                level: CUSTODY_DURABLE,
                recheck_s: 30
            }
        ),
        other => panic!("{other:?}"),
    }
    // APPEND: an empty tail is the batch itself, a tail is copied, and a dest past the bindings is a FAULT.
    match delivered_from(1, Some((1, &b""[..])), None, 2).unwrap() {
        Delivered::Append {
            dest,
            bytes,
            accepted,
        } => assert_eq!((dest, bytes, accepted), (1, None, 1)),
        other => panic!("{other:?}"),
    }
    match delivered_from(1, Some((0, &b"x\n"[..])), None, 2).unwrap() {
        Delivered::Append { bytes, .. } => assert_eq!(bytes.as_deref(), Some(&b"x\n"[..])),
        other => panic!("{other:?}"),
    }
    assert!(delivered_from(1, Some((2, &b""[..])), None, 2).is_err());
}

#[test]
#[ignore = "owner: W1-K8C; blocked (re-checked on dev 2026-11-16): the kernel export pump, DiskSink and stream routing are not on dev (OUTSTANDING row 4)"]
fn delivery_ids_resends_and_acks() {
    todo!("owner: W1-K8C (C-EXPORT-DELIVERY)")
}

#[test]
#[ignore = "owner: W1-K3; blocked (re-checked on dev 2026-11-16): the export breaker lives in the export pump, which is not on dev (OUTSTANDING row 4); the backoff schedule itself is covered by busbar-kernel retry tests"]
fn backoff_waits_and_breaker() {
    todo!("owner: W1-K3 (C-EXPORT-DELIVERY)")
}
