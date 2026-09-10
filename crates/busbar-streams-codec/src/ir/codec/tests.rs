// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE IR'S OWN STATE, tested with no dialect in the room: the playback position a barge-in
//! truncates at, the format arithmetic it divides by, and the two per-session tables and their
//! ceilings. Every test that asserts a dialect's bytes lives beside that dialect's reader.

use super::*;
use crate::ir::usage::IrDuplexUsage;

// ── playback position ────────────────────────────────────────────────────────────────────────────

#[test]
fn a_faster_than_realtime_burst_reports_the_audio_relayed_not_the_audio_heard() {
    // WHAT THE COUNTER MEANS. The upstream emits a whole turn's audio in one burst, far faster than
    // it plays. The position is derived from BYTES RELAYED, so after the burst it reads the whole
    // turn — an UPPER BOUND on what the user heard, not a measurement of it.
    let mut st = DecodeState::default();
    st.set_output_format(MediaFormat::Pcm16); // 48 B/ms
    st.record_played(48 * 10_000); // ten seconds of audio, handed over at once
    assert_eq!(
        st.played_ms(),
        10_000,
        "the bytes relayed for this item, in ms"
    );

    // THE SEAM A CLOCK GOES THROUGH. Fed how long the item has actually been playing, the position
    // is bounded by it: no more audio can have been heard than there has been time to hear it in.
    let mut st = DecodeState::default();
    st.set_output_format(MediaFormat::Pcm16);
    st.record_played_at(48 * 10_000, Some(1_200));
    assert_eq!(
        st.played_ms(),
        1_200,
        "1.2 s of wall clock cannot have played 10 s of audio"
    );
    // And a clock that has run longer than the audio relayed does not invent audio.
    let mut st = DecodeState::default();
    st.set_output_format(MediaFormat::Pcm16);
    st.record_played_at(48 * 100, Some(9_000));
    assert_eq!(st.played_ms(), 100, "only the audio actually handed over");
}
// ── barge-in truncate math ───────────────────────────────────────────────────────────────────────

#[test]
fn audio_format_math() {
    assert_eq!(MediaFormat::Pcm16.bytes_per_ms(), 48);
    assert_eq!(MediaFormat::G711Ulaw.bytes_per_ms(), 8);
    assert_eq!(MediaFormat::Pcm16.bytes_to_ms(480), 10);
    assert_eq!(MediaFormat::Pcm16.ms_to_bytes(10), 480);
    assert_eq!(MediaFormat::G711Ulaw.bytes_to_ms(80), 10);
    assert_eq!(
        crate::ir::media::truncate_point_ms(480, MediaFormat::Pcm16),
        10
    );
}

#[test]
fn flush_playback_returns_heard_ms_and_resets() {
    let mut st = DecodeState::default();
    st.set_output_format(MediaFormat::Pcm16);
    st.record_played(48 * 500); // 500 ms played
    assert_eq!(st.played_ms(), 500);
    let heard = st.flush_playback();
    assert_eq!(heard, 500);
    assert_eq!(st.played_ms(), 0, "flush zeroes the playback counter");
}
/// THE CALL-ID CORRELATION TABLE HAS A CEILING.
///
/// Nothing removes from it within a session — not even an item removal — so a client
/// that mints distinct `call_id`s grows it for as long as the call lasts. The table is a
/// correlation convenience, not a ledger: past the documented ceiling the OLDEST entry goes, and a
/// re-sighting of an evicted id correlates as a new call rather than keeping the map growing.
#[test]
fn the_call_id_table_is_capped_and_evicts_the_oldest() {
    let mut st = DecodeState::default();
    let first = st.ref_for_call_id("call-0");
    for i in 1..=MAX_TRACKED_CALL_IDS {
        st.ref_for_call_id(&format!("call-{i}"));
    }
    assert_eq!(
        st.call_ids.len(),
        MAX_TRACKED_CALL_IDS,
        "the table stays at its ceiling however many distinct call ids arrive"
    );
    assert!(
        !st.call_ids.contains_key("call-0"),
        "the OLDEST id is the one evicted"
    );
    assert_ne!(
        st.ref_for_call_id("call-0"),
        first,
        "an evicted id correlates as a new call rather than resurrecting its old handle"
    );
    // The most recent ids are still correlated, which is the whole point of keeping the table.
    let newest = format!("call-{MAX_TRACKED_CALL_IDS}");
    let handle = st.ref_for_call_id(&newest);
    assert_eq!(st.ref_for_call_id(&newest), handle);
}

/// THE HELD TOOL-ARGUMENT TABLE HAS THE SAME CEILING.
///
/// Only a call that CLOSES gives its accumulation back, and an upstream that streams argument
/// fragments is under no obligation to ever close one. Bounding the SIZE of each accumulation is no
/// bound on how many there are: a peer that opens calls and abandons them held one buffer per call
/// for the life of the session, each up to the per-call ceiling. Past the ceiling the oldest
/// accumulation goes, exactly as the oldest call id does.
#[test]
fn the_held_tool_argument_table_is_capped_and_evicts_the_oldest() {
    let mut st = DecodeState::default();
    // Every call opens, streams a fragment, and is never closed — the shape that grew the table.
    for i in 0..=MAX_TRACKED_CALL_IDS {
        let call = st.ref_for_call_id(&format!("call-{i}"));
        st.push_call_args(call, br#"{"a":"#);
    }
    assert_eq!(
        st.call_args.len(),
        MAX_TRACKED_CALL_IDS,
        "the held-arguments table stays at its ceiling however many calls are abandoned open"
    );
    assert!(
        st.take_call_args(CallRef(0)).is_none(),
        "the OLDEST accumulation is the one given up"
    );
    // A call that closed frees its place rather than spending one: the accumulation still held for
    // the newest call must survive a further ceiling's worth of closes.
    let newest = st.ref_for_call_id(&format!("call-{MAX_TRACKED_CALL_IDS}"));
    for i in 0..MAX_TRACKED_CALL_IDS {
        let call = st.ref_for_call_id(&format!("closed-{i}"));
        st.push_call_args(call, br#"{"b":1}"#);
        assert!(st.take_call_args(call).is_some());
    }
    st.push_call_args(newest, br#"1}"#);
    assert_eq!(
        st.take_call_args(newest),
        Some(serde_json::json!({"a": 1})),
        "a live accumulation is not evicted by calls that already closed"
    );
}

// ── the billing fold ─────────────────────────────────────────────────────────────────────────────

/// The cached figure a dialect reports is a SUBSET of the input figure it sits beside, so the fold
/// bills the UNCACHED remainder as `input` and the cached portion as `cache_read` — never the full
/// input figure alongside the cache figure, which would charge the cached tokens on both lanes.
#[test]
fn cached_input_tokens_are_not_billed_twice() {
    let u = IrDuplexUsage {
        audio_in: 1000,
        audio_out: 0,
        text_in: 0,
        text_out: 0,
        cached: 800,
    };
    let billed = u.to_billing_usage();
    assert_eq!(
        billed.usage_units.get(busbar_api::UNIT_INPUT).copied(),
        Some(200),
        "input bills the UNCACHED remainder (1000 - 800), not the full input figure"
    );
    assert_eq!(
        billed.usage_units.get(busbar_api::UNIT_CACHE_READ).copied(),
        Some(800),
        "the cached subset bills once, on the cache-read lane"
    );
    assert_eq!(
        billed.usage_units.values().sum::<u64>(),
        1000,
        "the billed lanes sum to the turn's input, never to 1800"
    );
}
