//! Tests for `raw.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

#[test]
fn parses_a_request_line_and_headers() {
    let raw = b"GET /v1/models HTTP/1.1\r\nHost: example\r\nContent-Length: 3\r\n\r\nabc";
    let msg = parse_message(raw).unwrap();
    assert_eq!(
        msg.start,
        RawStartLine::Request {
            method: "GET".to_string(),
            path: "/v1/models".to_string()
        }
    );
    assert_eq!(msg.headers[0], ("Host".to_string(), "example".to_string()));
    assert_eq!(msg.body, b"abc");
}

#[test]
fn a_chunked_body_survives_arriving_one_byte_at_a_time() {
    // The boundary that matters: a size line, a chunk's data, the CRLF after it and the
    // trailer section are all free to be split by the network wherever it likes.
    let wire = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Checksum: 7\r\n\r\n";
    let mut decoder = ChunkedDecoder::default();
    for byte in wire {
        assert!(!decoder.is_done());
        decoder.feed(&[*byte]).unwrap();
    }
    assert!(decoder.is_done());
    let (chunks, trailers) = decoder.take();
    assert_eq!(chunks, vec![b"Wiki".to_vec(), b"pedia".to_vec()]);
    assert_eq!(trailers, vec![("X-Checksum".to_string(), "7".to_string())]);
}

#[test]
fn a_chunked_body_with_no_trailers_ends_at_the_terminal_chunk() {
    let mut decoder = ChunkedDecoder::default();
    decoder.feed(b"3\r\nabc\r\n0\r\n\r\n").unwrap();
    assert!(decoder.is_done());
    let (chunks, trailers) = decoder.take();
    assert_eq!(chunks, vec![b"abc".to_vec()]);
    assert!(trailers.is_empty());
}

#[test]
fn a_size_line_that_is_not_hexadecimal_is_a_framing_error() {
    let mut decoder = ChunkedDecoder::default();
    assert_eq!(decoder.feed(b"zz\r\n"), Err(ChunkedMalformed));
}

#[test]
fn chunk_extensions_are_ignored_rather_than_read() {
    let mut decoder = ChunkedDecoder::default();
    decoder.feed(b"3;name=value\r\nabc\r\n0\r\n\r\n").unwrap();
    assert!(decoder.is_done());
    assert_eq!(decoder.take().0, vec![b"abc".to_vec()]);
}

#[test]
fn the_declared_length_and_coding_are_read_whatever_the_header_casing() {
    let headers = vec![
        ("CONTENT-length".to_string(), " 12 ".to_string()),
        ("Transfer-Encoding".to_string(), "gzip, Chunked".to_string()),
    ];
    assert_eq!(content_length(&headers), Ok(Some(12)));
    assert!(is_chunked(&headers));
    assert!(!is_chunked(&[(
        "Transfer-Encoding".to_string(),
        "gzip".to_string()
    )]));
}

/// Whitespace between a field name and its colon is refused, not normalised away.
///
/// RFC 9112 is explicit that a server MUST reject such a message: the historical divergence in
/// how intermediaries handled it is a request-smuggling surface, and trimming the name turns a
/// header no compliant peer would honour into one this transport does.
#[test]
fn whitespace_before_the_colon_is_refused_rather_than_trimmed() {
    assert_eq!(
        parse_message(b"GET / HTTP/1.1\r\nContent-Length : 5\r\n\r\n"),
        None
    );
    assert_eq!(
        parse_message(b"GET / HTTP/1.1\r\nTransfer-Encoding\t: chunked\r\n\r\n"),
        None
    );
    // The legal shape still parses, value whitespace and all.
    let ok = parse_message(b"GET / HTTP/1.1\r\nContent-Length:  5 \r\n\r\n").unwrap();
    assert_eq!(ok.headers[0].1, "5");
}

/// `chunked` is the LAST coding or the message is not chunked at all.
///
/// A sender that applies any other coding must apply `chunked` as the final one, precisely so
/// the message stays framable; a `Transfer-Encoding` where it is not final leaves the body
/// length undeterminable, and a reader that took it for chunked anyway would be decoding a
/// framing the sender never wrote.
#[test]
fn chunked_counts_only_as_the_final_transfer_coding() {
    assert!(is_chunked(&[(
        "Transfer-Encoding".to_string(),
        "gzip, chunked".to_string()
    )]));
    assert!(!is_chunked(&[(
        "Transfer-Encoding".to_string(),
        "chunked, gzip".to_string()
    )]));
    // And a coding list that names one at all is still a declared coding, chunked or not.
    assert!(has_transfer_encoding(&[(
        "Transfer-Encoding".to_string(),
        "chunked, gzip".to_string()
    )]));
    assert!(!has_transfer_encoding(&[(
        "Content-Length".to_string(),
        "5".to_string()
    )]));
}

#[test]
fn parses_a_status_line() {
    let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    let msg = parse_message(raw).unwrap();
    assert_eq!(
        msg.start,
        RawStartLine::Status {
            code: 404,
            reason: "Not Found".to_string()
        }
    );
    assert!(msg.body.is_empty());
}
