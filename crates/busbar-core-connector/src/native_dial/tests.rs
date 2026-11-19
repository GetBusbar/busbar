// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The native dial's pure parts: the scheme table, the head an answer is handed up as, and core's own reading
//! of an answer's status. The dial itself is proved end to end through the default distribution's linked http
//! image (`dist/default/tests/default_distribution_serves_from_min3_images.rs`).

use super::*;
use busbar_plugin_abi::plane::{CARRIER_HTTP, CARRIER_WEBSOCKET};

#[test]
fn every_row_of_the_scheme_table_and_its_default_port() {
    let cases = [
        (
            "http://api.example/v1",
            "api.example:80",
            None,
            false,
            CARRIER_HTTP,
        ),
        (
            "https://api.example/v1",
            "api.example:443",
            Some("api.example"),
            true,
            CARRIER_HTTP,
        ),
        (
            "HTTPS://api.example:8443",
            "api.example:8443",
            Some("api.example"),
            true,
            CARRIER_HTTP,
        ),
        (
            "ws://rt.example/x",
            "rt.example:80",
            None,
            false,
            CARRIER_WEBSOCKET,
        ),
        (
            "wss://rt.example/x",
            "rt.example:443",
            Some("rt.example"),
            true,
            CARRIER_WEBSOCKET,
        ),
        (
            "http://127.0.0.1:9000?q",
            "127.0.0.1:9000",
            None,
            false,
            CARRIER_HTTP,
        ),
        (
            "https://[::1]:8443/p",
            "[::1]:8443",
            Some("::1"),
            true,
            CARRIER_HTTP,
        ),
        (
            "https://[::1]",
            "[::1]:443",
            Some("::1"),
            true,
            CARRIER_HTTP,
        ),
    ];
    for (target, authority, name, secure, carrier) in cases {
        let located = locate(target).unwrap_or_else(|why| panic!("{target}: {why}"));
        assert_eq!(located.authority, authority, "{target}");
        assert_eq!(located.name.as_deref(), name, "{target}");
        assert_eq!(located.secure, secure, "{target}");
        assert_eq!(located.carrier, carrier, "{target}");
    }
}

#[test]
fn a_scheme_core_does_not_dial_and_a_malformed_authority_are_refused() {
    for target in [
        "sse://api.example",
        "grpc://api.example",
        "tcp://10.0.0.1:5432",
        "stdio://prog",
        "webrtc://x",
        "api.example/v1",
        "https://",
        "https://user:pw@api.example",
        "https://api.example:0",
        "https://api.example:70000",
        "https://[::1",
        "https://[::1]x",
    ] {
        assert!(locate(target).is_err(), "{target} must be refused");
    }
}

fn records(write: impl FnOnce(&mut Fixed<'_>)) -> Vec<u8> {
    let mut bytes = vec![0_u8; 4096];
    let len = {
        let mut writer = Fixed::new(&mut bytes);
        write(&mut writer);
        writer.len()
    };
    bytes.truncate(len);
    bytes
}

#[test]
fn an_answer_head_is_one_field_block_with_its_status_and_no_hop_by_hop_field() {
    let head = records(|w| {
        w.put_pod(tag::H_STATUS, &U32Rec { value: 429, _r: 0 })
            .unwrap();
        w.put_pair(tag::PAIR, "content-type", b"application/json")
            .unwrap();
        w.put_pair(tag::PAIR, "Connection", b"keep-alive, x-private")
            .unwrap();
        w.put_pair(tag::PAIR, "x-private", b"hop").unwrap();
        w.put_pair(tag::PAIR, "transfer-encoding", b"chunked")
            .unwrap();
        w.put_pair(tag::PAIR, "content-length", b"17").unwrap();
        w.put_pair(tag::PAIR, "retry-after", b"7").unwrap();
    });
    let Inbound::Head {
        status,
        declared_len,
        block,
    } = head_of(&head, false).expect("a head")
    else {
        panic!("not a head");
    };
    assert_eq!(status, Some(429));
    assert_eq!(declared_len, Some(17));
    assert_eq!(
        block.as_slice(),
        b"content-type: application/json\r\ncontent-length: 17\r\nretry-after: 7\r\n"
    );
    assert_eq!(retry_after(block.as_slice()), Some(7));
    assert!(
        head_of(&head, true).is_err(),
        "a second head on one stream is refused"
    );
}

#[test]
fn core_reads_an_answer_status_by_the_table_the_old_transport_stated() {
    assert_eq!(class_of(200), WireStatusClass::Success);
    assert_eq!(class_of(404), WireStatusClass::CallerFault);
    assert_eq!(class_of(503), WireStatusClass::FarEndFault);
    assert_eq!(class_of(101), WireStatusClass::Other);
    assert_eq!(fault_of(200), None);
    assert_eq!(fault_of(400), Some(WireFault::Caller));
    assert_eq!(fault_of(401), Some(WireFault::Hard));
    assert_eq!(fault_of(403), Some(WireFault::Hard));
    assert_eq!(fault_of(408), Some(WireFault::Transient));
    assert_eq!(fault_of(429), Some(WireFault::RateLimit));
    assert_eq!(fault_of(499), Some(WireFault::Caller));
    assert_eq!(fault_of(500), Some(WireFault::Transient));
    assert_eq!(fault_of(599), Some(WireFault::Transient));
}
