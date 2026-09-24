// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BEHAVIORAL BILLING PROOF for the voice plane — the ledger-level twin of the LLM plane's
//! crossproto_delivery_billing oracle. The `plane_meter_seam_reachability` gate proves voice *calls*
//! the core Meter seam; THIS test proves the spend actually *lands on the one ledger*, attributed to
//! the presenting key, exactly as marketing states: "the token counts land on the ledger when the
//! response stream completes."
//!
//! It drives a voice turn's usage through the SHIPPED path — `SessionCore`'s per-turn metering, which
//! reports the turn to the kernel's session account (`host.meter_ledger`) — over a GOVERNED host, then
//! reads the key's usage back off the host's ledger. A voice session that "bills nobody" (the pre-fix
//! state) reads back zero tokens; a fixed one reads the turn.
//!
//! The host is the substrate's in-memory fixture host with governance ON: its `meter_ledger` seam is
//! the one ledger this test reads back (`ledger_usage(key)`), keyed by the presenting key exactly as
//! the engine's `usage_for(key)` is. Whether the engine's own ledger accrues what its seam is handed
//! is the engine's money-path suite to prove; this plane's tests do not link the engine.

use crate::ir::usage::IrDuplexUsage;
use crate::runtime::metering::TurnMeter;
use crate::testkit::fixture_host::FixtureHost;
use busbar_plane_streaming::session::TurnCounters;
use std::sync::Arc;

/// A governed fixture: a host with governance ON and a virtual key presenting to it — so the host
/// `meter_ledger` seam the voice session drives writes to the very ledger this test reads back.
fn governed_fixture() -> (Arc<FixtureHost>, busbar_api::VirtualKey) {
    let host = Arc::new(FixtureHost::new().governed());
    let key = busbar_api::VirtualKey {
        id: "vk-voice-caller".to_string(),
        name: "voice-caller".to_string(),
        ..Default::default()
    };
    (host, key)
}

/// A voice turn's usage report: `input` audio tokens in, `output` audio tokens out.
fn turn_usage(input: u64, output: u64) -> IrDuplexUsage {
    IrDuplexUsage {
        audio_in: input,
        audio_out: output,
        ..IrDuplexUsage::default()
    }
}

#[test]
fn a_voice_turn_lands_spend_on_the_presenting_keys_ledger() {
    let (host, key) = governed_fixture();

    // Before: the key has metered nothing.
    let before = host
        .ledger_usage(&key.id)
        .map(|u| (u.tokens, u.requests))
        .unwrap_or((0, 0));
    assert_eq!(before, (0, 0), "a fresh key has no ledgered usage");

    // Drive ONE voice turn's usage through the SHIPPED Meter seam — the exact call `SessionCore`
    // makes per turn (the kernel session account → `host.meter_ledger`).
    let meter = TurnMeter::new(
        Arc::clone(&host) as Arc<dyn busbar_kernel::plane_host::EngineHost>,
        key.clone(),
        "voice-server",
        crate::OPENAI_REALTIME,
    );
    let session = meter
        .open("voice-model")
        .expect("an uncapped chain opens")
        .expect("a governed host opens an account");
    let _ = session.report_turn(Some(&turn_usage(300, 120)), TurnCounters::default());

    // After: the turn's tokens (300 + 120) landed on the presenting key's ledger — voice now bills
    // the caller through the ONE ledger, exactly like a model call or a tool call. THIS is the proof
    // that the Meter step works end-to-end at the ledger, not just at the wiring.
    let after = host
        .ledger_usage(&key.id)
        .expect("the key now has a materialised bucket");
    assert_eq!(
        after.tokens, 420,
        "the voice turn's 420 tokens must land on the one ledger (input 300 + output 120)"
    );
    // `requests` is the billable-REQUEST count, incremented by the ADMIT step's per-request fee
    // (`govern_admit`), NOT by the Meter step. Voice does not yet run Admit's fee charge — that is the
    // tracked next increment — so this reads 0 today. Pinned so that when Admit lands for voice, this
    // assertion flips RED and this test is the reminder to update it (and confirm the fee is charged).
    assert_eq!(
        after.requests, 0,
        "voice does not yet run the Admit per-request fee (tracked increment); flip this when it does"
    );
}

#[test]
fn an_ungoverned_voice_turn_meters_nobody_without_panicking() {
    // No governance configured: the host mints no meter pin, so no account opens (a voice session on
    // an ungoverned deployment opens and runs, it simply attributes to no ledger).
    let host = FixtureHost::new().into_host();
    let key = busbar_api::VirtualKey {
        id: "anon".to_string(),
        ..Default::default()
    };
    let meter = TurnMeter::new(host, key, "voice-server", crate::OPENAI_REALTIME);
    // Must not panic even though there is no ledger to write to.
    assert!(matches!(meter.open("voice-model"), Ok(None)));
    let _ = turn_usage(10, 5);
}

/// **EVERY ROW A VOICE SESSION'S METERING WRITES IS THE STREAMS PLANE'S** (#47, OWNER RULING Q32).
///
/// `GET /admin/usage` knows a metering row as a plane's row by its `provider` column naming a
/// registered plane key; any other row is a pools row, priced at the pools plane's flat
/// `per_request_fee:` per request. Each turn used to write a series row with the UPSTREAM dialect
/// label (`openai_realtime`) as its provider — a pools row — so, with a flat fee of 5, a three-turn
/// session read 15 on `/admin/usage` while the budget book (which charges a turn no per-request fee)
/// read 0. The turn's counts now reach the metering row only through the kernel's one accrual
/// (`meter_ledger`), on the plane-qualified lane the kernel keys by this plane: `/admin/usage` reads
/// 0, as the book does, and the session's own fee (`streams.fees.per_session`) is the fee lane's.
#[test]
fn a_voice_sessions_metering_writes_no_row_keyed_by_the_upstream_provider() {
    let (host, key) = governed_fixture();
    let meter = TurnMeter::new(
        Arc::clone(&host) as Arc<dyn busbar_kernel::plane_host::EngineHost>,
        key.clone(),
        "voice-server",
        crate::OPENAI_REALTIME,
    );
    let session = meter
        .open("gpt-realtime")
        .expect("an uncapped chain opens")
        .expect("a governed host opens an account");
    for _ in 0..3 {
        let _ = session.report_turn(Some(&turn_usage(30, 4)), TurnCounters::default());
    }

    assert_eq!(
        host.series_rows(&key.id),
        Vec::<(String, String)>::new(),
        "a turn is not a request: no per-turn series row (one keyed by the upstream provider \
         reads as a pools row, charged the flat per_request_fee per turn on /admin/usage)"
    );
    let plane_lane = format!(
        "{}{}",
        crate::PLANE_KEY,
        busbar_kernel::governance::PLANE_LANE_SEP
    );
    let rows = host.ledger_rows(&key.id);
    assert!(
        rows.keys().all(|(lane, _)| lane.starts_with(&plane_lane)),
        "every count lands on a lane qualified by this plane's key: {rows:?}"
    );
    assert_eq!(
        rows.get(&(
            format!("{plane_lane}gpt-realtime"),
            "audio_tokens_in".to_string()
        )),
        Some(&90),
        "the three turns' counts, on the plane-qualified model lane"
    );
}
