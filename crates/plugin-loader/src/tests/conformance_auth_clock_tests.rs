// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn scheduled_mint_fold(before: &str, after: &str) -> (Style, Fold) {
    let style = Style::parse(&serde_json::json!({
        "style": "scheduled", "head": {"method": "GET", "authority": "example.test", "target": "/", "timestamp": 1800000000},
        "expect_fields": [["authorization", "Bearer minted"]],
        "refreshed_fields": [["authorization", "Bearer refreshed"]],
        "expires_in": 60, "refusal": "Failed",
        "token_endpoint": [{"expect_request": {"method": "POST", "target": "https://issuer.test/token"}, "respond": {"status": 200, "body": "{}"}}]
    }));
    let fold = [
        ("validate", "Ready lease=false"),
        ("open", "Ready lease=false"),
        ("open_outbound", "Ready lease=false"),
        ("close", "Ready lease=false"),
        ("fields before the first mint", before),
        ("tick: the first mint", "Ready exchanges=1"),
        ("fields #1", after),
        ("fields #2", after),
        ("exchanges across the two calls", "exchanges=1 [ok]"),
        ("outbound_ready", "Ready ready=1"),
        ("fields after close", "Refused closed"),
        ("refresh due ahead of expiry", "refresh_ahead=true"),
        ("tick: the refresh", "Ready exchanges=2"),
        (
            "fields after the refresh",
            style.minting.as_ref().unwrap().refreshed.as_str(),
        ),
        ("exchanges after the refresh", "exchanges=2 [ok, ok]"),
        ("failing endpoint: tick", "Ready exchanges=1"),
        (
            "failing endpoint: fields",
            "Failed token endpoint unavailable",
        ),
        ("failing endpoint: outbound_ready", "Ready ready=0"),
    ]
    .into_iter()
    .map(|(label, answer)| super::super::super::Step {
        label: format!("outbound scheduled #0: {label}"),
        answer: answer.to_owned(),
        crossed: 1,
        pinned: 1,
        resumes: 0,
    })
    .collect();
    (style, fold)
}

#[test]
fn a_scheduled_mint_accepts_explained_refusal_then_requires_the_minted_credential() {
    for refusal in [
        "Failed token not minted yet",
        "Refused token not minted yet",
    ] {
        let minted = expected(
            &serde_json::json!([["authorization", "Bearer minted"]]),
            "test fields",
        );
        let (style, fold) = scheduled_mint_fold(refusal, &minted);
        contract(&fold, &[style]);
        let (style, fold) = scheduled_mint_fold(refusal, "Ready fields=[]");
        assert!(
            catch_unwind(AssertUnwindSafe(|| contract(&fold, &[style]))).is_err(),
            "a successful mint must still present its credential"
        );
    }
}

#[test]
fn a_scheduled_mint_rejects_default_open_and_unexplained_answers_before_mint() {
    let minted = expected(
        &serde_json::json!([["authorization", "Bearer minted"]]),
        "test fields",
    );
    for before in [
        "Ready fields=[]",
        minted.as_str(),
        "Failed ",
        "Refused ",
        "Pending ",
    ] {
        let (style, fold) = scheduled_mint_fold(before, &minted);
        assert!(
            catch_unwind(AssertUnwindSafe(|| contract(&fold, &[style]))).is_err(),
            "accepted pre-mint answer {before}"
        );
    }
}

#[test]
fn the_outbound_dispatcher_serves_a_plausible_clock_and_advances_both_readings_together() {
    for timestamp in [1_440_938_160, 1_900_000_000] {
        let (clock, dispatcher) = clock_dispatcher(timestamp);
        let host = dispatcher
            .host_services()
            .expect("outbound clock is served");
        let start = host.now();
        assert!(start.wall_ns / NS >= 1_767_225_600);
        assert!(start.wall_ns / NS >= timestamp);
        assert_eq!(start.mono_ns, T0);

        clock.advance(T0 + 3 * NS);
        let refreshed = host.now();
        assert_eq!(refreshed.wall_ns - start.wall_ns, 3 * NS);
        assert_eq!(refreshed.mono_ns - start.mono_ns, 3 * NS);

        clock.advance(T0 + 11 * NS);
        let expired = host.now();
        assert_eq!(expired.wall_ns - start.wall_ns, 11 * NS);
        assert_eq!(expired.mono_ns - start.mono_ns, 11 * NS);

        clock.advance(T0);
        assert_eq!(
            host.now(),
            expired,
            "a stale tick cannot rewind either clock"
        );
    }
}

#[test]
fn the_outbound_clock_host_does_not_serve_credentials() {
    let (_, dispatcher) = clock_dispatcher(1_440_938_160);
    let host = dispatcher
        .host_services()
        .expect("outbound clock is served");
    let answer = host.records_secret(
        "token",
        "not-a-credential",
        Box::new(|_| panic!("unserved")),
    );
    let busbar_contract::services::Ran::Now(answer) = answer else {
        panic!("an unserved credential read cannot pend");
    };
    assert_eq!(answer.outcome, Outcome::Refused);
    assert!(answer.bytes.is_empty());
}
