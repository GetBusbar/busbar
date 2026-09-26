// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! GOVERNANCE-BUDGET capability cells (voice-client + voice-server) — GATE-VALID location.
//!
//! OWNER RULING Q21b: a voice session is governed by the kernel's budget view like every other plane.
//! Each closed turn's raw counts per streaming-plane class go to the kernel's session account, which
//! ledgers them and answers `MustClose` (a hard close) the moment the caller's chain reads dry; a
//! caller whose chain is already dry is refused at the open. These cells replace the D2 lease's
//! (whose names they keep, because `qa/capability-equality.json` cites them): the host here is the
//! fixture host with a COUNT cap — each count one unit of the ceiling — since what a count is worth is
//! the read-time view's, proven over the real engine in the composition root's tests.

use crate::ir::usage::IrDuplexUsage;
use crate::runtime::metering::{TurnMeter, TurnVerdict};
use crate::testkit::fixture_host::FixtureHost;
use busbar_plane_streaming::session::TurnCounters;
use std::sync::Arc;

fn caller() -> busbar_contract::records::VirtualKey {
    busbar_contract::records::VirtualKey {
        id: "vk-budget".to_string(),
        ..Default::default()
    }
}

fn meter(host: &Arc<FixtureHost>) -> TurnMeter {
    TurnMeter::new(
        Arc::clone(host) as Arc<dyn busbar_kernel::plane_host::EngineHost>,
        caller(),
        "voice-server",
        crate::OPENAI_REALTIME,
    )
}

/// One turn of `n` emitted audio tokens.
fn turn(n: u64) -> IrDuplexUsage {
    IrDuplexUsage {
        audio_out: n,
        ..IrDuplexUsage::default()
    }
}

/// voice-client cell: a session whose turns dry the caller's chain hard-closes, and stays closed.
#[test]
fn a_session_lease_settled_past_its_cap_hard_closes_and_refuses_further_spend() {
    let host = Arc::new(FixtureHost::new().governed().with_count_cap(5));
    let session = meter(&host).open("m").expect("room").expect("governed");
    let quiet = TurnCounters::default();
    assert_eq!(
        session.report_turn(Some(&turn(3)), quiet),
        TurnVerdict::Live,
        "3 of 5"
    );
    assert_eq!(
        session.report_turn(Some(&turn(3)), quiet),
        TurnVerdict::MustClose,
        "6 of 5: the chain is dry — a hard close"
    );
    assert_eq!(
        session.report_turn(Some(&turn(3)), quiet),
        TurnVerdict::MustClose,
        "past the cap the verdict stays a hard close"
    );
    assert_eq!(
        host.ledger_usage("vk-budget").map(|u| u.tokens),
        Some(9),
        "every delivered count is ledgered exactly, none dropped at the close"
    );
}

/// voice-server cell: the session's counts are ledgered on the PRESENTING key, the turn that dries its
/// chain closes the carrier, and that key's next session is refused at the open.
#[test]
fn the_session_lease_bills_the_presenting_key_and_refuses_past_the_cap_with_a_hard_close() {
    let host = Arc::new(FixtureHost::new().governed().with_count_cap(50));
    let session = meter(&host).open("m").expect("room").expect("governed");
    let quiet = TurnCounters::default();
    assert_eq!(
        session.report_turn(Some(&turn(20)), quiet),
        TurnVerdict::Live
    );
    assert_eq!(
        session.report_turn(Some(&turn(20)), quiet),
        TurnVerdict::Live
    );
    assert_eq!(
        host.ledger_rows("vk-budget")
            .get(&("voice\u{1f}m".to_string(), "audio_tokens_out".to_string()))
            .copied(),
        Some(40),
        "the presenting key's row, under the voice lane and the plane's own class"
    );
    assert_eq!(
        session.report_turn(Some(&turn(20)), quiet),
        TurnVerdict::MustClose,
        "60 of 50: a hard close"
    );
    assert!(
        meter(&host).open("m").is_err(),
        "the dry key's next session is refused at the open"
    );
}
