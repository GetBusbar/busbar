// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// A settings blob's bytes, as `validate`/`open` read them off the lent blob.
fn blob(s: &'static str) -> &'static [u8] {
    s.as_bytes()
}

/// The settings default to 1.5.5's posture, and a value of the wrong kind is refused by name.
#[test]
fn the_settings_read_at_their_paths_and_refuse_the_wrong_kind() {
    let (p, prior, h1) = read_settings(blob("{}")).expect("defaults");
    assert_eq!(p.keep_alive_interval, Some(Duration::from_secs(30)));
    assert_eq!(p.keep_alive_timeout, Duration::from_secs(10));
    assert!(p.adaptive_window);
    assert_eq!(p.request_timeout, Duration::from_secs(300));
    assert!(!prior && !h1);
    let (p, prior, h1) = read_settings(blob(
        r#"{"advanced.upstream_h2_prior_knowledge":true,"advanced.upstream_http1_only":true,
            "limits.upstream_request_timeout_secs":7,"limits.request_body_max_bytes":9}"#,
    ))
    .expect("set");
    assert!(prior && h1);
    assert_eq!(
        (p.request_timeout, p.max_body_bytes),
        (Duration::from_secs(7), 9)
    );
    assert_eq!(
        read_settings(blob(r#"{"advanced.upstream_http1_only":"yes"}"#)).err(),
        Some("settings: a value is not of its declared kind")
    );
    assert_eq!(read_settings(blob("[")).err(), Some("settings: not JSON"));
}

/// Each status band lands in its class; anything outside the three bands is other.
#[test]
fn a_status_code_maps_to_its_class() {
    assert_eq!(class_of(200), STATUS_SUCCESS);
    assert_eq!(class_of(429), STATUS_CALLER_FAULT);
    assert_eq!(class_of(503), STATUS_FAR_END_FAULT);
    assert_eq!(class_of(101), STATUS_OTHER);
}

/// `locate`'s protocol offer is 1.5.5's client's ALPN offer: `h2, http/1.1` on a secured target,
/// `http/1.1` alone under the http1-only key, and none on a cleartext one.
#[test]
fn locate_offers_what_1_5_5_offered_in_the_handshake() {
    let http1_only = |s: &'static str| read_settings(blob(s)).expect("settings").2;
    assert_eq!(offer_for(true, http1_only("{}")), b"\x02h2\x08http/1.1");
    assert_eq!(
        offer_for(true, http1_only(r#"{"advanced.upstream_http1_only":true}"#)),
        b"\x08http/1.1"
    );
    assert_eq!(offer_for(false, http1_only("{}")), b"");
    assert_eq!(offer_for(false, true), b"");
}

/// RED: the head is the field block — lower-case names, hyper's (1.5.5's) order with a repeated
/// field on its own lines after its first, values unaltered — and no hop-by-hop field (the fixed
/// list, and what `connection` names: a `connection:`, `te:` or `upgrade:` line in the wire input
/// never appears as a framed field) nor `content-length` ever enters it.
#[test]
fn the_field_block_keeps_order_and_duplicates_and_drops_hop_by_hop() {
    let mut h = http::HeaderMap::new();
    for (n, v) in [
        ("X-B", "1"),
        ("Connection", "keep-alive, X-Hop"),
        ("x-a", "v: w"),
        ("Keep-Alive", "timeout=5"),
        ("x-b", "2"),
        ("X-Hop", "secret"),
        ("TE", "trailers"),
        ("Upgrade", "h2c"),
        ("Transfer-Encoding", "chunked"),
        ("Content-Length", "5"),
        ("X-Session-Id", "s1"),
    ] {
        h.append(
            http::header::HeaderName::from_bytes(n.as_bytes()).unwrap(),
            http::HeaderValue::from_static(v),
        );
    }
    assert_eq!(
        String::from_utf8(engine::field_block(&h)).unwrap(),
        "x-b: 1\r\nx-b: 2\r\nx-a: v: w\r\nx-session-id: s1\r\n"
    );
    assert!(engine::field_block(&http::HeaderMap::new()).is_empty());
}
