// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-EXPORT-DELIVERY (d) (IF §8.5 round 33, §49), kernel arms: delivery ids, resends, partial ACKs, custody
//! counting and the per-instance breaker cell.

use std::collections::HashSet;
use std::time::Duration;

use busbar_contract::export_stream::ExportStream;
use busbar_plugin_abi::export::{CUSTODY_ACCEPTED, CUSTODY_DURABLE, CUSTODY_INDEXED, CUSTODY_NONE};
use busbar_plugin_abi::fail::failed::{F_BUSY, F_LIMIT, F_UNAVAILABLE};

use super::{
    count_custody, custody_level_token, process_ids, Admit, Delivery, DeliveryIds, ExportBreaker,
    Outcome, BREAKER_OPENS_AFTER, EXPORT_CUSTODY_TOTAL, RETRY_AFTER_CLAMP_S,
};

/// Every delivery id is non-zero and distinct over a run, and 0 is skipped when the counter wraps.
#[test]
fn delivery_ids_are_non_zero_and_distinct() {
    let ids = DeliveryIds::from_seed(u64::MAX - 2);
    let minted: Vec<u64> = (0..6).map(|_| ids.mint()).collect();
    assert!(minted.iter().all(|&id| id != 0), "{minted:?}");
    assert_eq!(
        minted.iter().collect::<HashSet<_>>().len(),
        minted.len(),
        "{minted:?}"
    );

    let process = process_ids().expect("the crypto backend seeds the counter");
    let again = process_ids().expect("seeded once");
    assert!(std::ptr::eq(process, again), "one process-wide counter");
    let run: HashSet<u64> = (0..10_000).map(|_| process.mint()).collect();
    assert_eq!(run.len(), 10_000);
    assert!(!run.contains(&0));
}

/// A FAILED delivery is resent with the same id and `attempt` + 1; the first send is attempt 1.
#[test]
fn a_resend_keeps_the_id_and_counts_the_attempt() {
    let ids = DeliveryIds::from_seed(41);
    let first = Delivery::first(&ids);
    assert_eq!(first.attempt, 1);
    let resent = first.resend();
    assert_eq!((resent.id, resent.attempt), (first.id, 2));
    assert_eq!(resent.resend().attempt, 3);
}

/// ACK{2} of 5 lines keeps the id on lines 0..2 and resends 2..5 under a fresh id with `attempt` = 2.
#[test]
fn a_partial_ack_gives_the_remainder_a_fresh_id() {
    let ids = DeliveryIds::from_seed(7);
    let first = Delivery::first(&ids);
    let (kept, rest) = first.after_ack(2, 5, &ids).expect("three lines remain");
    assert_eq!(kept, 2);
    assert_ne!(rest.id, first.id);
    assert_ne!(rest.id, 0);
    assert_eq!(rest.attempt, 2);

    // A remainder of a resend counts from the parent's attempt.
    let (_, deeper) = rest
        .resend()
        .after_ack(1, 3, &ids)
        .expect("two lines remain");
    assert_eq!(deeper.attempt, 4);

    // Everything taken: nothing to resend; an ACK past the batch is clamped to it.
    assert_eq!(first.after_ack(5, 5, &ids), None);
    assert_eq!(first.after_ack(9, 5, &ids), None);
}

/// ACK{0}: no prefix was taken, so the same line set is resent under the same id.
#[test]
fn an_empty_ack_resends_the_same_line_set() {
    let ids = DeliveryIds::from_seed(100);
    let first = Delivery::first(&ids);
    assert_eq!(first.after_ack(0, 4, &ids), Some((0, first.resend())));
}

#[test]
fn custody_levels_have_their_tokens() {
    assert_eq!(custody_level_token(CUSTODY_ACCEPTED), Some("accepted"));
    assert_eq!(custody_level_token(CUSTODY_DURABLE), Some("durable"));
    assert_eq!(custody_level_token(CUSTODY_INDEXED), Some("indexed"));
    // NONE is a `confirm` answer only and above INDEXED is undefined: neither is ever counted.
    assert_eq!(custody_level_token(CUSTODY_NONE), None);
    assert_eq!(custody_level_token(4), None);
}

fn custody_count(instance: &str, stream: &str, level: &str) -> u64 {
    let families = crate::snapshot::snapshot().expect("the recorder is installed");
    families
        .iter()
        .filter(|f| f.name == EXPORT_CUSTODY_TOTAL)
        .flat_map(|f| f.samples.iter())
        .filter(|s| {
            let has = |k: &str, v: &str| s.labels.iter().any(|(lk, lv)| lk == k && lv == v);
            has("instance", instance) && has("stream", stream) && has("level", level)
        })
        .map(|s| s.value.parse::<u64>().expect("a counter value"))
        .sum()
}

/// An APPEND delivery counts `level="accepted"`; a LOGS answer CUSTODY{DURABLE, 10} is counted DURABLE.
#[test]
fn custody_is_counted_per_instance_stream_and_level() {
    crate::snapshot::init_for_test(Duration::from_secs(3600));
    count_custody("file-a", ExportStream::Logs, CUSTODY_ACCEPTED);
    count_custody("otlp-b", ExportStream::Logs, CUSTODY_DURABLE);
    count_custody("otlp-b", ExportStream::Logs, CUSTODY_DURABLE);
    count_custody("otlp-b", ExportStream::Events, CUSTODY_NONE);
    assert_eq!(custody_count("file-a", "logs", "accepted"), 1);
    assert_eq!(custody_count("otlp-b", "logs", "durable"), 2);
    assert_eq!(custody_count("otlp-b", "events", "none"), 0);
}

const NOW: u64 = 1_800_000_000;

fn failed(code: u32) -> Outcome {
    Outcome::Failed {
        code,
        retry_after_s: None,
    }
}

/// Five consecutive FAILED (other than F_BUSY) open the cell; F_BUSY feeds nothing; one half-open probe follows
/// the cooldown, and its success closes the cell.
#[test]
fn five_consecutive_failures_open_the_cell_and_one_probe_follows() {
    assert_eq!(BREAKER_OPENS_AFTER, 5);
    let b = ExportBreaker::new();
    for _ in 0..4 {
        b.record(NOW, failed(F_UNAVAILABLE));
        b.record(NOW, failed(F_BUSY));
    }
    assert_eq!(
        b.admit(NOW),
        Admit::Ready,
        "four FAILED and F_BUSY between them do not open it"
    );
    b.record(NOW, failed(F_LIMIT));
    let Admit::Held { until } = b.admit(NOW) else {
        panic!("the fifth consecutive FAILED opens the cell");
    };
    assert!(until > NOW && until <= NOW + RETRY_AFTER_CLAMP_S, "{until}");

    let later = NOW + RETRY_AFTER_CLAMP_S + 1;
    let Admit::Probe(epoch) = b.admit(later) else {
        panic!("a half-open probe after the cooldown");
    };
    assert!(
        matches!(b.admit(later), Admit::Held { .. }),
        "only one probe"
    );
    b.probe_done(epoch, later, Outcome::Delivered);
    assert_eq!(b.admit(later), Admit::Ready);
}

/// A success between failures resets the streak.
#[test]
fn a_delivery_between_failures_resets_the_streak() {
    let b = ExportBreaker::new();
    for _ in 0..4 {
        b.record(NOW, failed(F_UNAVAILABLE));
    }
    b.record(NOW, Outcome::Delivered);
    for _ in 0..4 {
        b.record(NOW, failed(F_UNAVAILABLE));
    }
    assert_eq!(b.admit(NOW), Admit::Ready);
}

/// A failed probe reopens the cell.
#[test]
fn a_failed_probe_reopens_the_cell() {
    let b = ExportBreaker::new();
    for _ in 0..5 {
        b.record(NOW, failed(F_UNAVAILABLE));
    }
    let later = NOW + RETRY_AFTER_CLAMP_S + 1;
    let Admit::Probe(epoch) = b.admit(later) else {
        panic!("probe");
    };
    b.probe_done(epoch, later, failed(F_UNAVAILABLE));
    assert!(matches!(b.admit(later), Admit::Held { .. }));
}

/// A Retry-After above 300 s holds the cell open for exactly the stated time, from the first such answer.
#[test]
fn a_long_retry_after_holds_the_cell_for_the_stated_time() {
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

    // At or below the clamp a Retry-After is the retry schedule's business (K3), not a hold.
    let short = ExportBreaker::new();
    short.record(
        NOW,
        Outcome::Failed {
            code: F_UNAVAILABLE,
            retry_after_s: Some(RETRY_AFTER_CLAMP_S),
        },
    );
    assert_eq!(short.admit(NOW), Admit::Ready);
}

/// REFUSED, FAULT and a deadline are not backend health: they never feed the cell.
#[test]
fn stops_feed_no_breaker() {
    let b = ExportBreaker::new();
    for _ in 0..10 {
        b.record(NOW, Outcome::NotHealth);
    }
    assert_eq!(b.admit(NOW), Admit::Ready);
}
