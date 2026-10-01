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

/// A field block is cut only at a line's start or inside a value, never inside a name: the host
/// refuses any continuation that does not extend a value.
#[test]
fn a_field_block_is_cut_only_where_a_continuation_extends_a_value() {
    let block = b"date: Mon\r\nx-a: 1\r\n";
    assert_eq!(field_cut(block, 64, false), block.len());
    // Inside "date": back to the start; just past the colon: a value.
    assert_eq!(field_cut(block, 3, false), 0);
    assert_eq!(field_cut(block, 5, false), 5);
    // Inside "x-a" on the second line: back to the line's start.
    assert_eq!(field_cut(block, 13, false), 11);
    // Opening inside a value, every byte up to the next name may go.
    assert_eq!(field_cut(b"on\r\nx: 1\r\n", 5, true), 4);
}

/// RED: the request target goes out as 1.5.5's client wrote it. A space is `%20`, an existing
/// `%20` is not encoded twice, and CR, LF and NUL are refused.
#[test]
fn a_target_is_percent_encoded_as_1_5_5_wrote_it() {
    let enc = |t: &str| String::from_utf8(target::encode_target(t.as_bytes()).unwrap()).unwrap();
    assert_eq!(
        enc("/v1beta/models/my model:generateContent"),
        "/v1beta/models/my%20model:generateContent"
    );
    assert_eq!(enc("/v1/a%20b"), "/v1/a%20b");
    for bad in ["/a\rb", "/a\nb", "/a\0b"] {
        assert_eq!(
            target::encode_target(bad.as_bytes()),
            Err(target::REFUSED),
            "{bad:?}"
        );
    }
}

/// The encoder IS the URL parser 1.5.5's client serialised a path with: the same bytes for every
/// target in the table.
#[test]
fn the_target_encoder_matches_the_url_parser_1_5_5_used() {
    let table = [
        "/v1/chat/completions",
        "/v1/models/my model:generateContent",
        "/v1/a%20b",
        "/v1/a%zz",
        "/v1/x?alt=sse",
        "/v1/x?q=a b&c=\"d\"",
        "/v1/x?q='quoted'",
        "/v1/x?q=<tag>#frag",
        "/v1/x#frag",
        "/v1/\"quoted\"/path",
        "/v1/<angle>",
        "/v1/`tick`",
        "/v1/{brace}",
        "/v1/pipe|caret^",
        "/v1/ümlaut/日本",
        "/v1/./a/../b",
        "/v1/%2e/a/%2E%2e/b",
        "/v1/a/..",
        "/v1/a/.",
        "/..",
        "",
        "/",
        "//double//slash",
        "\\v1\\back",
        "v1/relative",
        "/v1/ta\tb",
        "/v1/del\u{7f}",
        "/v1/ctl\u{1}",
        "/v1/x?",
        "/v1/x??y",
    ];
    for t in table {
        // 1.5.5 joined a base URL and an absolute path; a relative one is read as absolute.
        let absolute = if t.starts_with('/') || t.starts_with('\\') {
            t.to_owned()
        } else {
            format!("/{t}")
        };
        let url = url::Url::parse(&format!("http://h{absolute}")).unwrap();
        let want = &url[url::Position::BeforePath..url::Position::AfterQuery];
        let got = target::encode_target(t.as_bytes()).unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), want, "{t:?}");
    }
}
