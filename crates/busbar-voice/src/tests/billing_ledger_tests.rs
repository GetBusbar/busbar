// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BEHAVIORAL BILLING PROOF for the voice plane — the ledger-level twin of the LLM plane's
//! crossproto_delivery_billing oracle. The `plane_meter_seam_reachability` gate proves voice *calls*
//! the core Meter seam; THIS test proves the spend actually *lands on the one ledger*, attributed to
//! the presenting key, exactly as marketing states: "the token counts land on the ledger when the
//! response stream completes."
//!
//! It drives a voice turn's usage through the SHIPPED path — `SessionCore`'s per-turn metering, which
//! calls `TurnMeter::record_turn` → `host.meter_ledger`/`host.meter_series` — over a GOVERNED host,
//! then reads the key's usage back off the host's ledger. A voice session that "bills nobody" (the
//! pre-fix state) reads back zero tokens; a fixed one reads the turn.
//!
//! The host is the substrate's in-memory fixture host with governance ON: its `meter_ledger` seam is
//! the one ledger this test reads back (`ledger_usage(key)`), keyed by the presenting key exactly as
//! the engine's `usage_for(key)` is. Whether the engine's own ledger accrues what its seam is handed
//! is the engine's money-path suite to prove; this plane's tests do not link the engine.

use crate::runtime::metering::TurnMeter;
use busbar_substrate::testkit::fixture_host::FixtureHost;
use std::collections::BTreeMap;
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

/// A voice turn's usage carrier — the same neutral `billing::Usage` `to_billing_usage()` produces,
/// with the canonical `UNIT_INPUT`/`UNIT_OUTPUT` keys the rate card and ledger price against.
fn turn_usage(input: u64, output: u64) -> busbar_substrate::billing::Usage {
    let mut usage_units = BTreeMap::new();
    if input != 0 {
        usage_units.insert(busbar_api::UNIT_INPUT.to_string(), input);
    }
    if output != 0 {
        usage_units.insert(busbar_api::UNIT_OUTPUT.to_string(), output);
    }
    busbar_substrate::billing::Usage { usage_units }
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
    // makes per turn (`TurnMeter::record_turn` → `host.meter_ledger` + `host.meter_series`).
    let meter = TurnMeter::new(
        Arc::clone(&host) as Arc<dyn busbar_substrate::plane_host::EngineHost>,
        key.clone(),
        "voice-server",
        crate::OPENAI_REALTIME,
    );
    meter.record_turn("voice-model", &turn_usage(300, 120));

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
    // No governance configured: `host.governance()` is `None`, so `record_turn` no-ops cleanly (a
    // voice session on an ungoverned deployment opens and runs, it simply attributes to no ledger).
    let host = FixtureHost::new().into_host();
    let key = busbar_api::VirtualKey {
        id: "anon".to_string(),
        ..Default::default()
    };
    let meter = TurnMeter::new(host, key, "voice-server", crate::OPENAI_REALTIME);
    // Must not panic even though there is no ledger to write to.
    meter.record_turn("voice-model", &turn_usage(10, 5));
}
