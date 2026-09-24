// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VOICE PLANE-UNIT BILLING ORACLE — the regression backstop for the voice money path, replacing
//! the D2 lease oracle (`voice_d2_lease_billing_oracle`, deleted with the lease under OWNER RULING
//! Q21b; snapshot under `~/Downloads/busbar-1.6.0-snapshots/P2-voice/`).
//!
//! It drives the SAME fixed session script the lease oracle pinned — a refused open, then four turns
//! against a ceiling of 15 — through the path that now ships: each turn's raw counts per streaming-
//! plane class to the kernel's session account, which ledgers them and answers the verdict off the
//! caller's budget view. Every count ledgered and every verdict is pinned. The fixture host's view is
//! a count cap (each count worth one unit of the ceiling), the plane-unit twin of the lease oracle's
//! one-nano-per-unit mock, so the arithmetic stays legible; what a count is worth under a real
//! `streams` card is pinned over the engine in the composition root's tests.
//!
//! What moved, stated once: the lease folded the five token classes onto the llm plane's reserved
//! keys (so a turn's text and audio were one `output` figure) and stored a nanodollar sum; the plane
//! ledgers each class as itself, plus the two counts the lease never billed (`audio_seconds_in`,
//! `tool_calls`), and stores no figure.

use crate::ir::usage::IrDuplexUsage;
use crate::runtime::metering::{TurnMeter, TurnVerdict};
use crate::testkit::fixture_host::FixtureHost;
use busbar_plane_streaming::session::TurnCounters;
use std::collections::BTreeMap;
use std::sync::Arc;

const LANE: &str = "voice\u{1f}gpt-realtime";

fn key() -> busbar_api::VirtualKey {
    busbar_api::VirtualKey {
        id: "vk-oracle".to_string(),
        ..Default::default()
    }
}

fn meter(host: &Arc<FixtureHost>) -> TurnMeter {
    TurnMeter::new(
        Arc::clone(host) as Arc<dyn busbar_kernel::plane_host::EngineHost>,
        key(),
        "voice-server",
        crate::OPENAI_REALTIME,
    )
}

fn rows(host: &FixtureHost) -> BTreeMap<String, u64> {
    host.ledger_rows(&key().id)
        .into_iter()
        .map(|((lane, class), n)| {
            assert_eq!(lane, LANE);
            (class, n)
        })
        .collect()
}

fn pinned(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
    pairs.iter().map(|(c, n)| ((*c).to_string(), *n)).collect()
}

/// THE ORACLE — one session's whole metering life, every count and verdict pinned.
#[test]
fn voice_plane_unit_billing_oracle() {
    // ── LEG 0 — A DRY CHAIN IS REFUSED AT THE OPEN, AND NOTHING IS LEDGERED ─────────────────────────
    let dry = Arc::new(FixtureHost::new().governed().with_count_cap(0));
    assert!(
        meter(&dry).open("gpt-realtime").is_err(),
        "a chain with nothing left refuses the open"
    );
    assert!(rows(&dry).is_empty(), "a refused session ledgers nothing");

    // ── THE SESSION — a ceiling of 15 ───────────────────────────────────────────────────────────────
    let host = Arc::new(FixtureHost::new().governed().with_count_cap(15));
    let session = meter(&host)
        .open("gpt-realtime")
        .expect("room opens")
        .expect("governed");
    let no_counters = TurnCounters::default();

    // ── LEG 1 — turn 1: audio_out 3, text_out 4 → 7 of 15, Live ─────────────────────────────────────
    let v1 = session.report_turn(
        Some(&IrDuplexUsage {
            audio_out: 3,
            text_out: 4,
            ..IrDuplexUsage::default()
        }),
        no_counters,
    );
    assert_eq!(v1, TurnVerdict::Live);
    assert_eq!(
        rows(&host),
        pinned(&[("audio_tokens_out", 3), ("text_tokens_out", 4)]),
        "each class ledgered as itself — not one folded `output` of 7"
    );

    // ── LEG 2 — turn 2: audio_out 2, text_in 3, plus a second of uplink audio and a tool call ───────
    let mut counters = TurnCounters::default();
    counters.admit_audio(crate::ir::media::AudioFormat::Pcm16, 48_000);
    counters.open_tool_call();
    let v2 = session.report_turn(
        Some(&IrDuplexUsage {
            audio_out: 2,
            text_in: 3,
            ..IrDuplexUsage::default()
        }),
        counters,
    );
    assert_eq!(v2, TurnVerdict::Live, "7 + 5 + 1 s + 1 call = 14 of 15");
    assert_eq!(
        rows(&host),
        pinned(&[
            ("audio_seconds_in", 1),
            ("audio_tokens_out", 5),
            ("text_tokens_in", 3),
            ("text_tokens_out", 4),
            ("tool_calls", 1),
        ]),
        "the two counts the lease never billed are ledgered beside the tokens"
    );

    // ── LEG 3 — turn 3: audio_out 5 → 19 of 15, MustClose (delivered, ledgered, then closed) ────────
    let v3 = session.report_turn(
        Some(&IrDuplexUsage {
            audio_out: 5,
            ..IrDuplexUsage::default()
        }),
        no_counters,
    );
    assert_eq!(v3, TurnVerdict::MustClose);
    assert_eq!(rows(&host)["audio_tokens_out"], 10);

    // ── LEG 4 — once dry, stays dry: a late turn is still ledgered exactly and still closes ─────────
    let late = session.report_turn(
        Some(&IrDuplexUsage {
            audio_out: 1,
            ..IrDuplexUsage::default()
        }),
        no_counters,
    );
    assert_eq!(late, TurnVerdict::MustClose);
    assert_eq!(rows(&host)["audio_tokens_out"], 11);
    assert_eq!(
        host.ledger_usage(&key().id).map(|u| u.tokens),
        Some(20),
        "every count ledgered once: 7 + 7 + 5 + 1"
    );

    // ── LEG 5 — an empty turn ledgers nothing ───────────────────────────────────────────────────────
    let _ = session.report_turn(None, no_counters);
    assert_eq!(host.ledger_usage(&key().id).map(|u| u.tokens), Some(20));
}
