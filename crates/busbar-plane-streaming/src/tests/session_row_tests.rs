// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/session_row.rs`.

use super::*;

fn row(terminal: bool) -> VoiceSessionRow {
    VoiceSessionRow {
        id: "call-1".into(),
        owner: "acct".into(),
        turns: 3,
        updated_at: 1_700,
        terminal,
        rtc_call_id: None,
    }
}

/// The record a row is kept as: this plane's audit kind, the turn cursor as its sequence, the last
/// mutation as its timestamp, and a disposition that follows the row's terminal flag.
#[test]
fn a_row_is_kept_as_its_own_record() {
    let live = row(false).record();
    assert_eq!(live.kind, "voice_session");
    assert_eq!(live.id, "call-1");
    assert_eq!(live.seq, 3);
    assert_eq!(live.ts, 1_700);
    assert!(matches!(live.disposition, PlaneDisposition::Active));
    assert!(matches!(
        row(true).record().disposition,
        PlaneDisposition::Terminal
    ));
}

/// The record's body IS the row, and a row written before `rtc_call_id` existed still reads back.
#[test]
fn the_record_body_reads_back_as_the_row() {
    let r = row(false);
    let back: VoiceSessionRow =
        serde_json::from_slice(&r.record().body).expect("the body is the row");
    assert_eq!(back, r);
    let older: VoiceSessionRow = serde_json::from_str(
        r#"{"id":"call-1","owner":"acct","turns":3,"updated_at":1700,"terminal":false}"#,
    )
    .expect("a row without rtc_call_id reads back");
    assert_eq!(older, r);
}
