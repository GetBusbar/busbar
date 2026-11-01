// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

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
