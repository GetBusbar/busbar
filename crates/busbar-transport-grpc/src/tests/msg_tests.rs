// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the gRPC layer's bytes: framing, timeouts, statuses, `grpc-message` and the head block.

use super::*;

// ── frame and Messages ───────────────────────────────────────────────────────────────────────────

#[test]
fn an_empty_payload_is_still_a_five_byte_frame() {
    assert_eq!(frame(b""), vec![0, 0, 0, 0, 0]);
}

#[test]
fn a_frame_carries_a_big_endian_length_before_the_payload() {
    let payload = vec![7u8; 258];
    let f = frame(&payload);
    assert_eq!(&f[..5], &[0, 0, 0, 1, 2]);
    assert_eq!(&f[5..], payload.as_slice());
    assert_eq!(f.len(), PREFIX + 258);
}

#[test]
fn several_messages_in_one_push_come_out_in_order() {
    let mut m = Messages::new(64);
    let mut wire = frame(b"one");
    wire.extend(frame(b""));
    wire.extend(frame(b"three"));
    let out = m.push(&wire).unwrap();
    assert_eq!(out.len(), 3);
    assert_eq!(&out[0][..], frame(b"one").as_slice());
    assert_eq!(&out[1][..], frame(b"").as_slice());
    assert_eq!(&out[2][..], frame(b"three").as_slice());
    assert_eq!(m.end(), Ok(()));
}

#[test]
fn a_message_split_across_pushes_comes_out_whole() {
    let mut m = Messages::new(64);
    let wire = frame(b"hello world");
    assert!(m.push(&wire[..3]).unwrap().is_empty());
    assert!(m.push(&wire[3..9]).unwrap().is_empty());
    assert_eq!(m.end(), Err(Bad::Truncated));
    let out = m.push(&wire[9..]).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0][..], wire.as_slice());
    assert_eq!(m.end(), Ok(()));
}

#[test]
fn a_compressed_flag_is_refused() {
    let mut m = Messages::new(64);
    assert_eq!(m.push(&[1, 0, 0, 0, 0]), Err(Bad::Compressed));
}

#[test]
fn an_oversize_length_is_refused_before_the_body_arrives() {
    let mut m = Messages::new(4);
    assert_eq!(m.push(&[0, 0, 0, 0, 5]), Err(Bad::TooLarge(5)));
    // exactly the ceiling is fine
    let mut ok = Messages::new(4);
    assert_eq!(ok.push(&frame(b"abcd")).unwrap().len(), 1);
}

#[test]
fn a_stream_that_ends_inside_a_message_is_truncated() {
    let mut m = Messages::new(64);
    assert!(m.push(&frame(b"abc")[..6]).unwrap().is_empty());
    assert_eq!(m.end(), Err(Bad::Truncated));
    assert!(Bad::Truncated.to_string().contains("inside a message"));
}

#[test]
fn a_stream_that_ends_between_messages_is_clean() {
    let m = Messages::new(64);
    assert_eq!(m.end(), Ok(()));
}

// ── grpc-timeout ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_short_timeout_stays_in_nanoseconds() {
    assert_eq!(timeout_value(Duration::from_nanos(1500)), "1500n");
    assert_eq!(timeout_value(Duration::ZERO), "0n");
}

#[test]
fn a_timeout_too_long_for_nanoseconds_rounds_up_into_microseconds() {
    // 1_000_000_001 ns needs ten digits in `n`; in `u` it is 1_000_000.001, rounded up.
    assert_eq!(
        timeout_value(Duration::from_nanos(1_000_000_001)),
        "1000001u"
    );
}

#[test]
fn a_long_timeout_moves_to_seconds_minutes_and_hours() {
    assert_eq!(timeout_value(Duration::from_secs(100_000)), "100000S");
    assert_eq!(timeout_value(Duration::from_secs(100_000_000)), "1666667M");
    assert_eq!(
        timeout_value(Duration::from_secs(10_000_000_000)),
        "2777778H"
    );
    assert_eq!(timeout_value(Duration::from_secs(u64::MAX)), "99999999H");
}

#[test]
fn a_timeout_value_never_has_more_than_eight_digits() {
    for ns in [0u64, 1, 99_999_999, 100_000_000, 1 << 40, u64::MAX] {
        let v = timeout_value(Duration::from_nanos(ns));
        assert!(v.len() <= 9, "{v}");
    }
}

#[test]
fn a_timeout_round_trips_through_parse_timeout() {
    for d in [
        Duration::from_nanos(1500),
        Duration::from_millis(250),
        Duration::from_secs(2),
        Duration::from_secs(100_000),
    ] {
        assert_eq!(parse_timeout(timeout_value(d).as_bytes()), Some(d));
    }
}

#[test]
fn every_timeout_unit_is_read() {
    assert_eq!(parse_timeout(b"5n"), Some(Duration::from_nanos(5)));
    assert_eq!(parse_timeout(b"5u"), Some(Duration::from_micros(5)));
    assert_eq!(parse_timeout(b"5m"), Some(Duration::from_millis(5)));
    assert_eq!(parse_timeout(b"5S"), Some(Duration::from_secs(5)));
    assert_eq!(parse_timeout(b"5M"), Some(Duration::from_secs(300)));
    assert_eq!(parse_timeout(b"5H"), Some(Duration::from_secs(18_000)));
}

#[test]
fn a_malformed_timeout_is_refused() {
    assert_eq!(parse_timeout(b""), None);
    assert_eq!(parse_timeout(b"S"), None);
    assert_eq!(parse_timeout(b"5"), None);
    assert_eq!(parse_timeout(b"123456789S"), None);
    assert_eq!(parse_timeout(b"5x"), None);
    assert_eq!(parse_timeout(b"1aS"), None);
    assert_eq!(parse_timeout(b"-1S"), None);
}

// ── grpc-status ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn an_http_status_maps_to_its_grpc_status() {
    assert_eq!(status_of_http(400), INTERNAL);
    assert_eq!(status_of_http(401), UNAUTHENTICATED);
    assert_eq!(status_of_http(403), PERMISSION_DENIED);
    assert_eq!(status_of_http(404), UNIMPLEMENTED);
    for code in [429, 502, 503, 504] {
        assert_eq!(status_of_http(code), UNAVAILABLE, "{code}");
    }
    assert_eq!(status_of_http(500), UNKNOWN);
    assert_eq!(status_of_http(200), UNKNOWN);
}

#[test]
fn a_grpc_status_is_read_within_the_canonical_range() {
    assert_eq!(parse_status(b"0"), OK);
    assert_eq!(parse_status(b"16"), 16);
    assert_eq!(parse_status(b" 5 "), 5);
}

#[test]
fn an_out_of_range_or_unreadable_grpc_status_is_unknown() {
    assert_eq!(parse_status(b"17"), UNKNOWN);
    assert_eq!(parse_status(b"x"), UNKNOWN);
    assert_eq!(parse_status(b""), UNKNOWN);
    assert_eq!(parse_status(&[0xff]), UNKNOWN);
}

// ── grpc-message ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_percent_escape_is_decoded() {
    assert_eq!(decode_message(b"a%20b"), b"a b");
    assert_eq!(decode_message(b"%20"), b" ");
    assert_eq!(decode_message(b"%C3%A9"), "é".as_bytes());
}

#[test]
fn a_malformed_or_cut_escape_stays_as_sent() {
    assert_eq!(decode_message(b"%zz"), b"%zz");
    assert_eq!(decode_message(b"ab%4"), b"ab%4");
    assert_eq!(decode_message(b"%"), b"%");
}

#[test]
fn encoding_escapes_controls_percent_and_non_ascii() {
    assert_eq!(encode_message(b"plain text"), "plain text");
    assert_eq!(encode_message(b"a\r\nb"), "a%0D%0Ab");
    assert_eq!(encode_message(b"100%"), "100%25");
    assert_eq!(encode_message("é".as_bytes()), "%C3%A9");
    assert_eq!(encode_message(&[0x7f]), "%7F");
}

#[test]
fn an_encoded_message_decodes_back_to_the_original() {
    let text = "bad \"req\": 100% \u{1F600} é\r\n\t\0".as_bytes();
    assert_eq!(decode_message(encode_message(text).as_bytes()), text);
}

// ── content type ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_grpc_content_type_is_recognised_with_or_without_a_suffix() {
    assert!(is_grpc_content_type(b"application/grpc"));
    assert!(is_grpc_content_type(b"application/grpc+proto"));
    assert!(is_grpc_content_type(b"application/grpc;charset=x"));
    assert!(is_grpc_content_type(b"Application/GRPC"));
}

#[test]
fn a_look_alike_content_type_is_not_grpc() {
    assert!(!is_grpc_content_type(b"application/grpcx"));
    assert!(!is_grpc_content_type(b"application/json"));
    assert!(!is_grpc_content_type(b"application/grp"));
    assert!(!is_grpc_content_type(b""));
}

// ── the head block ───────────────────────────────────────────────────────────────────────────────

#[test]
fn an_incomplete_head_block_is_not_yet_a_head() {
    assert_eq!(read_head(b"", 100), Ok(None));
    assert_eq!(read_head(b"path: /a/B\r\n", 100), Ok(None));
    assert_eq!(read_head(b"path: /a/B\r\n\r", 100), Ok(None));
}

#[test]
fn a_blank_line_alone_is_an_empty_head() {
    let (head, took) = read_head(b"\r\nrest", 100).unwrap().unwrap();
    assert_eq!(head, Head::default());
    assert_eq!(took, 2);
}

#[test]
fn field_names_are_lowercased_and_values_trimmed() {
    let (head, _) = read_head(b"Path:   /a/B \r\nTE : trailers\r\n\r\n", 100)
        .unwrap()
        .unwrap();
    assert_eq!(head.get("path"), Some(&b"/a/B"[..]));
    assert_eq!(head.get("PATH"), Some(&b"/a/B"[..]));
    assert_eq!(head.get("te"), Some(&b"trailers"[..]));
    assert_eq!(head.get("missing"), None);
    assert_eq!(head.fields[0].0, "path");
    assert_eq!(head.content_length, None);
}

#[test]
fn content_length_is_parsed_and_kept_out_of_the_fields() {
    let (head, _) = read_head(b"a: b\r\nContent-Length: 42\r\n\r\n", 100)
        .unwrap()
        .unwrap();
    assert_eq!(head.content_length, Some(42));
    assert_eq!(head.fields.len(), 1);
    assert_eq!(head.get("content-length"), None);
}

#[test]
fn a_bad_content_length_is_an_error() {
    assert!(read_head(b"content-length: many\r\n\r\n", 100).is_err());
    assert!(read_head(b"content-length: -1\r\n\r\n", 100).is_err());
}

#[test]
fn a_head_line_without_a_colon_is_an_error() {
    assert!(read_head(b"nonsense\r\n\r\n", 100).is_err());
}

#[test]
fn a_field_with_no_name_is_an_error() {
    assert!(read_head(b": value\r\n\r\n", 100).is_err());
}

#[test]
fn an_incomplete_block_past_the_ceiling_is_an_error() {
    assert!(read_head(b"a: bbbbbbbbbbbbbbbbbbbb", 8).is_err());
    assert_eq!(read_head(b"a: b", 8), Ok(None));
}

#[test]
fn the_bytes_after_the_head_are_the_messages() {
    let mut wire = b"path: /a/B\r\ncontent-length: 8\r\n\r\n".to_vec();
    let head_len = wire.len();
    wire.extend(frame(b"abc"));
    let (head, took) = read_head(&wire, 100).unwrap().unwrap();
    assert_eq!(took, head_len);
    assert_eq!(head.content_length, Some(8));
    assert_eq!(&wire[took..], frame(b"abc").as_slice());
}

#[test]
fn a_head_renders_fields_then_content_length_then_a_blank_line() {
    let out = render_head(&[("path", b"/a/B"), ("te", b"trailers")], Some(7)).unwrap();
    assert_eq!(
        out,
        b"path: /a/B\r\nte: trailers\r\ncontent-length: 7\r\n\r\n"
    );
    assert_eq!(render_head(&[], None).unwrap(), b"\r\n");
}

#[test]
fn a_caller_content_length_field_is_skipped() {
    let out = render_head(&[("Content-Length", b"99"), ("a", b"b")], None).unwrap();
    assert_eq!(out, b"a: b\r\n\r\n");
    let out = render_head(&[("content-length", b"99")], Some(3)).unwrap();
    assert_eq!(out, b"content-length: 3\r\n\r\n");
}

#[test]
fn a_head_that_could_end_a_line_early_is_refused() {
    assert!(render_head(&[("a", b"x\r\ny: z")], None).is_err());
    assert!(render_head(&[("a", b"x\ny")], None).is_err());
    assert!(render_head(&[("a", b"x\ry")], None).is_err());
    assert!(render_head(&[("a", b"x\0y")], None).is_err());
    assert!(render_head(&[("a\r\nb", b"x")], None).is_err());
    assert!(render_head(&[("a\0b", b"x")], None).is_err());
    assert!(render_head(&[("a:b", b"x")], None).is_err());
    assert!(render_head(&[("", b"x")], None).is_err());
}

#[test]
fn a_rendered_head_reads_back_the_same() {
    let out = render_head(&[("path", b"/a/B"), ("x-k", b"v v")], Some(12)).unwrap();
    let (head, took) = read_head(&out, 1024).unwrap().unwrap();
    assert_eq!(took, out.len());
    assert_eq!(head.content_length, Some(12));
    assert_eq!(
        head.fields,
        vec![
            ("path".to_string(), b"/a/B".to_vec()),
            ("x-k".to_string(), b"v v".to_vec())
        ]
    );
}
