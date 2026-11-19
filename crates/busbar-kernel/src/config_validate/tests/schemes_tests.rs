// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_plugin_abi::plane::{CARRIER_RTC, CARRIER_STDIO};

/// Dial decision v2 section 3.2, row by row: (scheme, secured, default port, carrier for DEFAULT, carriers a
/// plane may name).
#[test]
fn every_row_of_the_table() {
    let rows: [(&str, bool, u16, u32, &[u32]); 4] = [
        (
            "http",
            false,
            80,
            CARRIER_HTTP,
            &[CARRIER_HTTP, CARRIER_GRPC],
        ),
        (
            "https",
            true,
            443,
            CARRIER_HTTP,
            &[CARRIER_HTTP, CARRIER_GRPC],
        ),
        ("ws", false, 80, CARRIER_WEBSOCKET, &[CARRIER_WEBSOCKET]),
        ("wss", true, 443, CARRIER_WEBSOCKET, &[CARRIER_WEBSOCKET]),
    ];
    for (scheme, secured, port, default, named) in rows {
        let row = dial_scheme(scheme).unwrap_or_else(|why| panic!("{scheme}: {why}"));
        assert_eq!(row.secured, secured, "{scheme} secured");
        assert_eq!(row.default_port, port, "{scheme} port");
        assert_eq!(
            row.carrier(CARRIER_DEFAULT),
            Ok(default),
            "{scheme} default"
        );
        for carrier in named {
            assert_eq!(
                row.carrier(*carrier),
                Ok(*carrier),
                "{scheme} names {carrier}"
            );
        }
        for carrier in [
            CARRIER_HTTP,
            CARRIER_GRPC,
            CARRIER_WEBSOCKET,
            CARRIER_RTC,
            CARRIER_STDIO,
        ] {
            if !named.contains(&carrier) {
                assert_eq!(
                    row.carrier(carrier),
                    Err(SchemeRefused::CarrierNotAllowed { scheme, carrier }),
                    "{scheme} must refuse {carrier}"
                );
            }
        }
    }
}

#[test]
fn the_carrier_numbers_are_the_design_s() {
    assert_eq!(
        [
            CARRIER_DEFAULT,
            CARRIER_HTTP,
            CARRIER_GRPC,
            CARRIER_WEBSOCKET,
            CARRIER_RTC,
            CARRIER_STDIO
        ],
        [0, 1, 2, 3, 4, 5]
    );
}

#[test]
fn a_resolved_carrier_is_never_the_default() {
    for scheme in ["http", "https", "ws", "wss"] {
        let row = dial_scheme(scheme).expect("a row");
        assert_ne!(row.carrier(CARRIER_DEFAULT), Ok(CARRIER_DEFAULT));
    }
}

#[test]
fn a_scheme_without_a_row_is_refused_naming_it_and_the_four_words() {
    for scheme in [
        "sse", "grpc", "tcp", "stdio", "webrtc", "ftp", "file", "ssh", "ws+tls", "h2", "", "http ",
        " https", "https:",
    ] {
        let why = dial_scheme(scheme).expect_err(scheme);
        assert_eq!(why, SchemeRefused::Unknown(scheme.to_owned()));
        let text = why.to_string();
        assert!(text.contains(&format!("`{scheme}`")), "{text}");
        for word in ["`http`", "`https`", "`ws`", "`wss`"] {
            assert!(text.contains(word), "{text} names {word}");
        }
    }
}

#[test]
fn a_destination_takes_its_scheme_from_before_the_first_separator() {
    assert_eq!(dial_scheme_of_url("https://api.example.com/v1"), Ok(HTTPS));
    assert_eq!(dial_scheme_of_url("http://127.0.0.1:8080"), Ok(HTTP));
    assert_eq!(
        dial_scheme_of_url("wss://rt.example.com/socket?a=b://c"),
        Ok(WSS)
    );
    assert_eq!(dial_scheme_of_url("ws://localhost"), Ok(WS));
    assert_eq!(
        dial_scheme_of_url("sse://host/x"),
        Err(SchemeRefused::Unknown("sse".into()))
    );
    assert_eq!(
        dial_scheme_of_url("webrtc://peer"),
        Err(SchemeRefused::Unknown("webrtc".into()))
    );
    assert_eq!(
        dial_scheme_of_url("api.example.com/v1"),
        Err(SchemeRefused::Missing)
    );
    assert_eq!(dial_scheme_of_url(""), Err(SchemeRefused::Missing));
    assert!(SchemeRefused::Missing.to_string().contains("`wss`"));
}

#[test]
fn schemes_compare_without_regard_to_case() {
    assert_eq!(dial_scheme("HTTPS"), Ok(HTTPS));
    assert_eq!(dial_scheme("Http"), Ok(HTTP));
    assert_eq!(dial_scheme_of_url("WSS://h"), Ok(WSS));
    assert_eq!(dial_scheme("Ws"), Ok(WS));
}

#[test]
fn websocket_over_an_https_destination_is_refused_until_a_row_says_otherwise() {
    let row = dial_scheme("https").expect("a row");
    assert_eq!(
        row.carrier(CARRIER_WEBSOCKET),
        Err(SchemeRefused::CarrierNotAllowed {
            scheme: "https",
            carrier: CARRIER_WEBSOCKET
        })
    );
}

#[test]
fn no_scheme_can_carry_webrtc_a_child_process_or_a_number_out_of_range() {
    for scheme in ["http", "https", "ws", "wss"] {
        let row = dial_scheme(scheme).expect("a row");
        for carrier in [CARRIER_RTC, CARRIER_STDIO, 6, 7, u32::MAX] {
            assert!(
                matches!(
                    row.carrier(carrier),
                    Err(SchemeRefused::CarrierNotAllowed { carrier: got, .. }) if got == carrier
                ),
                "{scheme} {carrier}"
            );
        }
    }
}

#[test]
fn the_refusal_text_for_a_carrier_names_the_scheme_and_the_number() {
    let text = dial_scheme("wss")
        .expect("a row")
        .carrier(CARRIER_GRPC)
        .expect_err("refused")
        .to_string();
    assert!(
        text.contains("carrier 2") && text.contains("`wss`"),
        "{text}"
    );
}
