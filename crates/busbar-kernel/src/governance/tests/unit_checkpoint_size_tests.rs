// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A selected checkpoint is refused when it could not be sealed within its byte bound. The sealed
//! size is measured without building the sealed record, and it is that record's encoded size to
//! the byte: measured as the bound always measured it (the streaming writer) and as the store
//! writes it.

use std::sync::Arc;

use super::*;
use crate::governance::recovery::{RecoveryEvent, RecoveryKind, RecoveryState};
use crate::governance::unit_checkpoint::partitions::{
    check_size, sealed_size, Disposition, MAX_AUDIT_BYTES,
};
use crate::governance::unit_checkpoint::UnitCheckpoint;
use busbar_contract::kept::Text;

/// Text a JSON writer must escape (a quote, a backslash, control bytes, the unit separator the
/// lanes use) beside text it must not (a slash, non-ASCII letters, an emoji, the line and
/// paragraph separators, a byte-order mark).
const AWKWARD: &str =
    "q\"b\\s/\u{0}\u{1}\u{8}\t\n\r\u{1f}\u{7f}\u{80}é日本🎉\u{2028}\u{2029}\u{feff}";

fn awkward() -> Text {
    Text::from(Arc::<str>::from(AWKWARD))
}

/// The bytes the sealed record writes: through the streaming writer the bound counts with, and
/// through the store's encoder. Both are asserted equal.
fn sealed_bytes(snapshot: &UnitCheckpoint, terminal: &[RecoveryEvent]) -> usize {
    let mut sealed = snapshot.clone();
    sealed.terminal = Some(terminal.to_vec());
    let mut streamed = Vec::new();
    json::to_writer(&mut streamed, &sealed).unwrap();
    let stored = json::to_vec(&sealed).unwrap();
    assert_eq!(
        streamed, stored,
        "the bound's writer and the store's encoder differ"
    );
    stored.len()
}

fn event(fill: u8, payload: Vec<u8>) -> RecoveryEvent {
    RecoveryEvent {
        operation_id: [fill; 16],
        revision: 0,
        previous_event: None,
        kind: RecoveryKind::Metering,
        body_fingerprint: [fill.wrapping_mul(7); 32],
        state: RecoveryState::Intent,
        first_sent_at_ms: Some(u64::from(fill) * 1_000_003),
        payload,
    }
}

/// `snapshot` with awkward text in every text it holds and every byte value in its audit.
fn awkward_snapshot(mut snapshot: UnitCheckpoint) -> UnitCheckpoint {
    snapshot.principal = AWKWARD.into();
    snapshot.group = AWKWARD.into();
    snapshot.targets[0].bucket = AWKWARD.into();
    snapshot.targets[0].group = Some(AWKWARD.into());
    snapshot.unread = Some(AWKWARD.into());
    snapshot.audit = Some((0..=255u8).collect::<Vec<_>>().into());
    let parts = snapshot.partitions.as_mut().unwrap();
    parts.request_pool = awkward();
    parts.session_origin.instance = awkward();
    parts.disposition = Disposition::Cancel { reason: awkward() };
    for attempt in &mut parts.attempts {
        attempt.resource = Some(awkward());
        attempt.usage.provider = Some(awkward());
    }
    snapshot
}

#[tokio::test]
async fn the_sealed_size_is_the_sealed_records_encoded_size() {
    let gov = governance().await;
    let prepared = prepared_selected(&gov).await;
    let committed = committed_selected(&prepared);
    let mut cases = Vec::new();
    for snapshot in [
        every_name(false),
        every_name(true),
        initial_selected(),
        prepared.as_ref().clone(),
        committed,
    ] {
        // The children the selected terminal would be sealed with now.
        let events = gov.unit_terminal_events(&snapshot).unwrap();
        cases.push((snapshot, events));
    }
    let odd = awkward_snapshot(every_name(true));
    for events in [
        Vec::new(),
        vec![event(1, (0..=255).collect())],
        vec![
            event(255, AWKWARD.as_bytes().to_vec()),
            event(0, Vec::new()),
            event(10, vec![0, 9, 10, 99, 100, 255]),
        ],
    ] {
        cases.push((odd.clone(), events));
    }
    // A snapshot that already holds a vector is measured with that vector replaced.
    let mut resealed = odd.clone();
    resealed.terminal = Some(vec![event(9, b"{}".to_vec()), event(200, vec![7; 300])]);
    cases.push((resealed, vec![event(3, b"[\"\\\"]".to_vec())]));
    // The bound's audit, of the widest byte spelling.
    let mut widest = every_name(false);
    widest.audit = Some(vec![0xff; MAX_AUDIT_BYTES].into());
    let events = gov.unit_terminal_events(&widest).unwrap();
    cases.push((widest, events));

    for (at, (snapshot, events)) in cases.iter().enumerate() {
        assert_eq!(
            sealed_size(snapshot, events),
            Some(sealed_bytes(snapshot, events)),
            "case {at}"
        );
    }
}

/// The capacity check allocates for the children it measures and for nothing else: no sealed
/// copy of the checkpoint is made to be measured.
#[tokio::test]
async fn the_capacity_check_builds_no_sealed_record() {
    let gov = governance().await;
    let prepared = prepared_selected(&gov).await;
    let mut committed = committed_selected(&prepared);
    committed.audit = Some(vec![b'a'; 4096].into());
    let facts = committed.partitions.as_mut().unwrap().attempts[0]
        .usage
        .classes
        .values_mut()
        .next()
        .unwrap();
    facts.reported = Some(Count::from(5u64));
    facts.rate_high_water = Count::from(5u64);
    let events = gov.unit_terminal_events(&committed).unwrap();
    assert!(!events.is_empty(), "the fixture seals children");
    drop(events);
    crate::ThreadAllocated::reset();
    drop(gov.unit_terminal_events(&committed).unwrap());
    let children = crate::ThreadAllocated::bytes();
    // Counting the snapshot's encoding allocates only what the encoder does on its own (a count
    // is spelled as text while it is written); that is the measuring the check must do anyway.
    crate::ThreadAllocated::reset();
    check_size(&committed).unwrap();
    let counting = crate::ThreadAllocated::bytes();
    crate::ThreadAllocated::reset();
    gov.validate_selected_terminal_capacity(&committed).unwrap();
    let checked = crate::ThreadAllocated::bytes();
    assert!(
        checked <= children + counting,
        "the capacity check allocated {checked} bytes; its children take {children} and \
         counting the snapshot {counting}"
    );
}
