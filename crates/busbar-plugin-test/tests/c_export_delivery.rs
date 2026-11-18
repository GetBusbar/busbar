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
use busbar_ports::codec::export::decode_delivery;

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
    // #236 (DES-EXPORT-1.6 r3): the ceiling, 4096, is admitted; above it is refused, never clamped.
    assert_eq!(
        run(&describe(&content, &[4096], false), M_DELIVER | M_CONFIRM).unwrap(),
        Some(4096)
    );
    assert!(run(&describe(&content, &[4097], false), M_DELIVER | M_CONFIRM).is_err());
    assert!(run(
        &describe(&content, &[u64::MAX], false),
        M_DELIVER | M_CONFIRM
    )
    .is_err());
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
    use busbar_ports::export::{Custody, Delivered};

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
    // APPEND: `dest` is the `{"$dest": n}` handle the binder wrote, numbered from 1 (ABI export AppendRec, IF
    // §12.7; core resolves it with `ConfigBinder::dest(instance, handle)`, dafbb2a9b3). An empty tail is the
    // batch itself, a tail is copied, and handle 0 or a handle past the bindings is a FAULT.
    match delivered_from(1, Some((1, &b""[..])), None, 1).unwrap() {
        Delivered::Append {
            dest,
            bytes,
            accepted,
        } => assert_eq!((dest, bytes, accepted), (1, None, 1)),
        other => panic!("{other:?}"),
    }
    match delivered_from(1, Some((2, &b"x\n"[..])), None, 2).unwrap() {
        Delivered::Append { bytes, .. } => assert_eq!(bytes.as_deref(), Some(&b"x\n"[..])),
        other => panic!("{other:?}"),
    }
    assert!(delivered_from(1, Some((0, &b""[..])), None, 2).is_err());
    assert!(delivered_from(1, Some((3, &b""[..])), None, 2).is_err());
}

#[test]
#[ignore = "owner: W1-K8C; re-checked 2026-11-16: the ids, resends and partial ACKs run as delivery_ids_resends_and_partial_acks_in_the_kernel_types below; the booted half (the pump minting an id per line set, an APPEND delivery counted accepted in export_custody_total, a LOGS answer CUSTODY{DURABLE, 10} never confirmed or paused, the admin instance view showing the ceiling) waits on open MR !2645 (kernel export pump and DiskSink, OUTSTANDING row 4)"]
fn delivery_ids_resends_and_acks() {
    todo!("owner: W1-K8C (C-EXPORT-DELIVERY)")
}

#[test]
#[ignore = "owner: W1-K3; re-checked 2026-11-16: the breaker clauses of (e) run as the sibling breaker tests below; the booted half (the pump waiting Backoff [floor, ceiling], Retry-After 30 giving a wait of at least 30 s, Retry-After 900 giving a 300 s wait with the cell open 900 s, a non-content delivery stopping after attempt 3) waits on open MR !2645 (the pump that drives the cell); the backoff schedule itself is covered by busbar-kernel retry tests"]
fn backoff_waits_and_breaker() {
    todo!("owner: W1-K3 (C-EXPORT-DELIVERY)")
}

// Sibling arms: the parts of (d) and (e) that run on the kernel's own delivery types (K8C and K3 landed
// `busbar_kernel::export::delivery`; the pump that drives them is open MR !2645).
mod kernel_types {
    use std::collections::HashSet;

    use busbar_kernel::export::delivery::{
        Admit, Delivery, DeliveryIds, ExportBreaker, Outcome, BREAKER_OPENS_AFTER,
        RETRY_AFTER_CLAMP_S,
    };
    use busbar_plugin_abi::fail::failed::{F_BUSY, F_LIMIT, F_UNAVAILABLE};

    const NOW: u64 = 1_800_000_000;

    fn failed(code: u32) -> Outcome {
        Outcome::Failed {
            code,
            retry_after_s: None,
        }
    }

    #[test]
    fn delivery_ids_resends_and_partial_acks_in_the_kernel_types() {
        // (d) every delivery id is non-zero and distinct over a run (the counter skips 0 when it wraps).
        let ids = DeliveryIds::from_seed(u64::MAX - 2);
        let minted: Vec<u64> = (0..8).map(|_| ids.mint()).collect();
        assert!(minted.iter().all(|&id| id != 0), "{minted:?}");
        assert_eq!(minted.iter().collect::<HashSet<_>>().len(), minted.len());

        // A FAILED delivery is resent with the same id and attempt + 1.
        let ids = DeliveryIds::from_seed(5);
        let first = Delivery::first(&ids);
        assert_eq!(first.attempt, 1);
        let resent = first.resend();
        assert_eq!((resent.id, resent.attempt), (first.id, 2));

        // ACK{2} of 5 lines keeps the id on lines 0..2 and resends 2..5 under a fresh id with attempt 2.
        let (kept, rest) = first.after_ack(2, 5, &ids).expect("three lines remain");
        assert_eq!(kept, 2);
        assert_ne!(rest.id, first.id);
        assert_ne!(rest.id, 0);
        assert_eq!(rest.attempt, 2);
        // Everything taken: nothing to resend.
        assert_eq!(first.after_ack(5, 5, &ids), None);
    }

    #[test]
    fn five_failed_open_the_export_breaker_and_one_probe_follows() {
        // (e) 5 consecutive FAILED open the cell and one half-open probe follows; F_BUSY feeds no breaker.
        assert_eq!(BREAKER_OPENS_AFTER, 5);
        let b = ExportBreaker::new();
        for _ in 0..4 {
            b.record(NOW, failed(F_UNAVAILABLE));
            b.record(NOW, failed(F_BUSY));
        }
        assert_eq!(b.admit(NOW), Admit::Ready, "F_BUSY feeds no breaker");
        b.record(NOW, failed(F_LIMIT));
        assert!(matches!(b.admit(NOW), Admit::Held { .. }));
        let later = NOW + RETRY_AFTER_CLAMP_S + 1;
        let Admit::Probe(epoch) = b.admit(later) else {
            panic!("one half-open probe follows the cooldown");
        };
        assert!(
            matches!(b.admit(later), Admit::Held { .. }),
            "only one probe"
        );
        b.probe_done(epoch, later, Outcome::Delivered);
        assert_eq!(b.admit(later), Admit::Ready);
    }

    #[test]
    fn a_long_retry_after_holds_the_cell_and_stops_do_not_feed_it() {
        // Retry-After 900 holds the cell open for 900 s; at the clamp it is the retry schedule's business.
        let b = ExportBreaker::new();
        b.record(
            NOW,
            Outcome::Failed {
                code: F_UNAVAILABLE,
                retry_after_s: Some(900),
            },
        );
        assert_eq!(b.admit(NOW + 899), Admit::Held { until: NOW + 900 });
        assert!(matches!(b.admit(NOW + 900), Admit::Probe(_)));
        let short = ExportBreaker::new();
        short.record(
            NOW,
            Outcome::Failed {
                code: F_UNAVAILABLE,
                retry_after_s: Some(RETRY_AFTER_CLAMP_S),
            },
        );
        assert_eq!(short.admit(NOW), Admit::Ready);
        // REFUSED and FAULT are not backend health.
        let stops = ExportBreaker::new();
        for _ in 0..10 {
            stops.record(NOW, Outcome::NotHealth);
        }
        assert_eq!(stops.admit(NOW), Admit::Ready);
    }
}
