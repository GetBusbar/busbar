// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The engine, both sides at once: a dialled [`Conn`] and an accepted one wired back to back, the
//! test carrying each one's wire bytes to the other and holding the clock.

use std::time::Duration;

use crate::hyper_io::{Owed, Piece};

use super::{Conn, Posture};
use crate::msg;

const SEC: u64 = 1_000_000_000;

fn posture() -> Posture {
    Posture {
        keep_alive_interval: None,
        keep_alive_timeout: Duration::from_secs(10),
        adaptive_window: false,
        timeout: Duration::from_secs(300),
        max_message_bytes: 1 << 20,
    }
}

/// A call as `encode` renders it: the head block (its fields and the message stream's length),
/// then the messages.
fn call(path: &str, extra: &[(&str, &[u8])], messages: &[&[u8]]) -> Vec<u8> {
    let body: Vec<u8> = messages.iter().flat_map(|m| msg::frame(m)).collect();
    let mut fields: Vec<(&str, &[u8])> = vec![("path", path.as_bytes())];
    fields.extend_from_slice(extra);
    let mut out = msg::render_head(&fields, Some(body.len())).expect("a head");
    out.extend_from_slice(&body);
    out
}

struct Pair {
    d: Conn,
    a: Conn,
    now: u64,
    got_d: Vec<Piece>,
    got_a: Vec<Piece>,
}

impl Pair {
    fn new() -> Self {
        let now = 5 * SEC;
        Self {
            d: Conn::dial("http://peer.test:50051", posture(), now).expect("dial"),
            a: Conn::accept(posture(), now),
            now,
            got_d: Vec::new(),
            got_a: Vec::new(),
        }
    }

    /// Drive both ends and carry bytes between them until neither has anything to move.
    fn settle(&mut self) {
        for _ in 0..200 {
            self.d.drive(self.now);
            self.a.drive(self.now);
            let to_a = self.d.take_wire(usize::MAX);
            let to_d = self.a.take_wire(usize::MAX);
            self.got_d.extend(self.d.pieces().drain(..));
            self.got_a.extend(self.a.pieces().drain(..));
            if to_a.is_empty() && to_d.is_empty() {
                return;
            }
            self.a.ingest(&to_a, false);
            self.d.ingest(&to_d, false);
        }
        panic!("the pair never settled");
    }

    fn at(&mut self, t: u64) {
        self.now = t;
        self.settle();
    }
}

/// A stream's pieces, in order.
fn of(got: &[Piece], stream: u64) -> Vec<&Piece> {
    got.iter().filter(|p| p.stream == stream).collect()
}

/// The stream's head: its FIRST piece, a field block with no status code.
fn head(got: &[Piece], stream: u64) -> &Piece {
    let h = of(got, stream)[0];
    assert!(h.fields && h.status.is_none(), "the head comes first: {h:?}");
    h
}

/// The stream's messages, then its empty end piece when the frames are over.
fn frames(got: &[Piece], stream: u64) -> Vec<&[u8]> {
    of(got, stream)
        .into_iter()
        .filter(|p| !p.fields && p.status.is_none() && !p.failed)
        .map(|p| p.bytes.as_ref())
        .collect()
}

/// The piece that states the stream's status: the trailers, or a failure no trailers came with.
fn terminal(got: &[Piece], stream: u64) -> Option<&Piece> {
    got.iter()
        .find(|p| p.stream == stream && p.status.is_some())
}

/// The stream's terminal piece after its trailers: empty on `OK`, else the failure.
fn last(got: &[Piece], stream: u64) -> Option<&Piece> {
    of(got, stream).last().copied()
}

/// A field block's value for `name`.
fn field(block: &[u8], name: &str) -> Option<Vec<u8>> {
    busbar_contract::abi::transport::fields::lines(block)
        .find(|(n, _)| n == &name.as_bytes())
        .map(|(_, v)| v.to_vec())
}

#[test]
fn a_unary_call_half_closes_and_its_answer_ends_with_status_ok() {
    let mut p = Pair::new();
    let c = call("/pkg.Svc/Say", &[("x-meta", b"one")], &[b"hello"]);
    p.d.emit(1, &c, true, 0, p.now).expect("emit");
    p.settle();

    // The accepted side sees the call's head (its head words in the slots, never as fields), its
    // one message, and the far end's last (the empty piece): the dialled side sent END_STREAM
    // after the message.
    let h = head(&p.got_a, 1);
    let words = h.head.as_ref().expect("an accepted head states its words");
    assert_eq!(words.method.as_ref(), b"POST");
    assert_eq!(words.target.as_ref(), b"/pkg.Svc/Say");
    assert_eq!(words.authority.as_ref(), b"peer.test:50051");
    assert_eq!(field(&h.bytes, "path"), None, "no pseudo-field");
    assert_eq!(
        field(&h.bytes, "content-type").as_deref(),
        Some(&b"application/grpc"[..])
    );
    assert_eq!(field(&h.bytes, "te"), None, "te is checked, then dropped");
    assert_eq!(field(&h.bytes, "x-meta").as_deref(), Some(&b"one"[..]));
    let a = frames(&p.got_a, 1);
    assert_eq!(a.len(), 2, "message, end: {a:?}");
    assert_eq!(a[0], msg::frame(b"hello").as_slice());
    assert!(a[1].is_empty(), "the far end's last");

    p.a.emit(1, b"\r\n", false, 0, p.now).expect("answer head");
    p.a.emit(1, &msg::frame(b"hi"), false, 0, p.now)
        .expect("answer message");
    p.a.end_call(1, b"grpc-status: 0\r\n").expect("end");
    p.settle();

    // The dialled side: the head (no code), the message, the trailers carrying grpc-status, and
    // the empty terminal piece.
    let h = head(&p.got_d, 1);
    assert!(h.head.is_none(), "an h2 answer has no reason phrase");
    let d = frames(&p.got_d, 1);
    assert_eq!(d, vec![msg::frame(b"hi").as_slice(), &b""[..]]);
    let t = terminal(&p.got_d, 1).expect("the trailers");
    assert!(t.fields && !t.failed);
    assert_eq!(t.status, Some(0));
    assert_eq!(field(&t.bytes, "grpc-status"), None, "the status is the code");
    let end = last(&p.got_d, 1).expect("a terminal piece");
    assert!(!end.fields && !end.failed && end.bytes.is_empty() && end.status.is_none());
}

#[test]
fn without_the_half_close_a_unary_peer_never_sees_the_calls_end() {
    // RED arm of the half-close: a call whose head states no length and whose frame does not end
    // leaves the request stream open, and the accepted side never sees the far end's last.
    let mut p = Pair::new();
    let mut c = msg::render_head(&[("path", b"/pkg.Svc/Say")], None).expect("head");
    c.extend_from_slice(&msg::frame(b"hello"));
    p.d.emit(1, &c, false, 0, p.now).expect("emit");
    p.settle();
    let a = frames(&p.got_a, 1);
    assert_eq!(a.len(), 1, "the message only: {a:?}");
    assert!(
        !a.iter().any(|f| f.is_empty()),
        "no end without the half-close"
    );
    // The frame's end is the half-close.
    p.d.emit(1, b"", true, 0, p.now).expect("end");
    p.settle();
    assert!(frames(&p.got_a, 1).last().is_some_and(|f| f.is_empty()));
}

#[test]
fn a_server_stream_carries_each_message_as_its_own_frame() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/List", &[], &[b"q"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    p.a.emit(1, b"x-answer: yes\r\n\r\n", false, 0, p.now)
        .expect("head");
    for m in [&b"a"[..], b"bb", b""] {
        p.a.emit(1, &msg::frame(m), false, 0, p.now)
            .expect("message");
        p.settle();
    }
    p.a.end_call(1, b"grpc-status: 0\r\n").expect("end");
    p.settle();
    assert_eq!(
        field(&head(&p.got_d, 1).bytes, "x-answer").as_deref(),
        Some(&b"yes"[..])
    );
    let d = frames(&p.got_d, 1);
    assert_eq!(
        d,
        vec![
            msg::frame(b"a").as_slice(),
            msg::frame(b"bb").as_slice(),
            msg::frame(b"").as_slice(),
            &b""[..],
        ]
    );
    assert_eq!(terminal(&p.got_d, 1).and_then(|t| t.status), Some(0));
}

#[test]
fn a_non_zero_status_fails_the_stream_with_the_decoded_message() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    p.a.emit(1, b"\r\n", false, 0, p.now).expect("head");
    p.a.end_call(1, b"grpc-status: 5\r\ngrpc-message: no%20such%20key\r\n")
        .expect("end");
    p.settle();
    let t = terminal(&p.got_d, 1).expect("the trailers");
    assert_eq!((t.status, t.fields), (Some(5), true));
    let end = last(&p.got_d, 1).expect("terminal");
    assert!(end.failed);
    assert_eq!(end.bytes.as_ref(), b"no such key");
}

#[test]
fn a_trailers_only_answer_carries_its_status_in_the_head() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    // Nothing emitted first: the status goes out in the one HEADERS frame.
    p.a.end_call(1, b"grpc-status: 7\r\ngrpc-message: denied\r\n")
        .expect("end");
    p.settle();
    assert!(frames(&p.got_d, 1).is_empty(), "no message");
    assert!(
        field(&head(&p.got_d, 1).bytes, "grpc-status").is_none(),
        "the status is the trailers' code"
    );
    let t = terminal(&p.got_d, 1).expect("the trailers");
    assert_eq!((t.status, t.fields), (Some(7), true));
    let end = last(&p.got_d, 1).expect("terminal");
    assert_eq!((end.failed, end.bytes.as_ref()), (true, &b"denied"[..]));
}

#[test]
fn a_refusal_without_a_status_is_unknown_with_its_text() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/Get", &[], &[b"k"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    p.a.end_call(1, b"it broke").expect("end");
    p.settle();
    let t = terminal(&p.got_d, 1).expect("the trailers");
    assert_eq!(t.status, Some(msg::UNKNOWN));
    let end = last(&p.got_d, 1).expect("terminal");
    assert_eq!(end.bytes.as_ref(), b"it broke");
}

#[test]
fn the_callers_deadline_goes_out_as_grpc_timeout_and_fails_the_call_when_it_passes() {
    let mut p = Pair::new();
    let t0 = p.now;
    p.d.emit(
        1,
        &call("/pkg.Svc/Slow", &[], &[b"q"]),
        true,
        t0 + 2 * SEC,
        t0,
    )
    .expect("emit");
    p.settle();
    assert_eq!(
        field(&head(&p.got_a, 1).bytes, "grpc-timeout").as_deref(),
        Some(&b"2000000u"[..])
    );
    assert_eq!(
        p.d.next_deadline(),
        Some(t0 + 2 * SEC),
        "the host is asked back at the deadline"
    );
    p.at(t0 + 2 * SEC - 1);
    assert!(terminal(&p.got_d, 1).is_none(), "not before the deadline");
    p.at(t0 + 2 * SEC);
    let t = terminal(&p.got_d, 1).expect("terminal");
    assert_eq!(t.status, Some(msg::DEADLINE_EXCEEDED));
    assert!(t.failed);
    assert!(p.d.failure().is_none(), "the connection lives on");
}

#[test]
fn an_accepted_call_past_its_grpc_timeout_ends_deadline_exceeded_both_ways() {
    let mut p = Pair::new();
    let t0 = p.now;
    p.d.emit(1, &call("/pkg.Svc/Slow", &[], &[b"q"]), true, t0 + SEC, t0)
        .expect("emit");
    p.settle();
    // Both clocks run: the dialled deadline and the accepted grpc-timeout are the same instant.
    p.at(t0 + SEC);
    let a = terminal(&p.got_a, 1).expect("the accepted side's terminal");
    assert_eq!(a.status, Some(msg::DEADLINE_EXCEEDED));
    let d = terminal(&p.got_d, 1).expect("the dialled side's terminal");
    assert_eq!(d.status, Some(msg::DEADLINE_EXCEEDED));
}

#[test]
fn two_calls_share_one_connection() {
    let mut p = Pair::new();
    p.d.emit(1, &call("/pkg.Svc/A", &[], &[b"1"]), true, 0, p.now)
        .expect("emit");
    p.d.emit(3, &call("/pkg.Svc/B", &[], &[b"3"]), true, 0, p.now)
        .expect("emit");
    p.settle();
    // The accepted side numbers calls in arrival order.
    let paths: Vec<_> = [1, 2]
        .iter()
        .map(|s| head(&p.got_a, *s).head.as_ref().map(|w| w.target.to_vec()))
        .collect();
    assert_eq!(
        paths,
        vec![Some(b"/pkg.Svc/A".to_vec()), Some(b"/pkg.Svc/B".to_vec())]
    );
    p.a.end_call(2, b"grpc-status: 0\r\n").expect("end 2");
    p.a.end_call(1, b"grpc-status: 0\r\n").expect("end 1");
    p.settle();
    assert_eq!(terminal(&p.got_d, 1).and_then(|t| t.status), Some(0));
    assert_eq!(terminal(&p.got_d, 3).and_then(|t| t.status), Some(0));
}

#[test]
fn a_bad_call_fails_its_own_stream_internal() {
    let mut p = Pair::new();
    let c = msg::render_head(&[("path", b"no-slash")], Some(0)).expect("head");
    p.d.emit(1, &c, true, 0, p.now).expect("emit");
    let t = terminal(&p.d.pieces().drain(..).collect::<Vec<_>>(), 1).cloned();
    let t = t.expect("terminal");
    assert_eq!(t.status, Some(msg::INTERNAL));
    assert!(t.failed);
}

#[test]
fn a_compressed_message_from_the_far_end_fails_the_call() {
    let mut p = Pair::new();
    let mut c = msg::render_head(&[("path", b"/pkg.Svc/Z")], Some(6)).expect("head");
    c.extend_from_slice(&[1, 0, 0, 0, 1, b'z']);
    p.d.emit(1, &c, true, 0, p.now).expect("emit");
    p.settle();
    let a = terminal(&p.got_a, 1).expect("the accepted side fails it");
    assert_eq!(a.status, Some(msg::INTERNAL));
    let d = terminal(&p.got_d, 1).expect("and answers the dialled side");
    assert_eq!(d.status, Some(msg::INTERNAL));
}

// ── te, as 1.5.5's server checked it (CORRECTION te) ─────────────────────────────────────────────

/// One HTTP/2 frame.
fn h2(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut v = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, ty, flags];
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// A client's preface and one HEADERS frame opening stream 1 with a gRPC call, `te` as given:
/// HPACK by hand (indexed and literal-without-indexing fields, no Huffman), so a field hyper's own
/// client would never send can be.
fn opening(te: Option<&str>) -> Vec<u8> {
    let lit = |out: &mut Vec<u8>, s: &str| {
        out.push(u8::try_from(s.len()).expect("short"));
        out.extend_from_slice(s.as_bytes());
    };
    let mut block = vec![0x83, 0x86]; // :method POST, :scheme http
    block.push(0x04); // :path, by its static name
    lit(&mut block, "/pkg.Svc/Say");
    block.push(0x01); // :authority
    lit(&mut block, "peer.test");
    block.extend_from_slice(&[0x0f, 0x10]); // content-type (static index 31)
    lit(&mut block, "application/grpc");
    if let Some(te) = te {
        block.push(0x00);
        lit(&mut block, "te");
        lit(&mut block, te);
    }
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend(h2(4, 0, 0, &[]));
    // END_HEADERS.
    out.extend(h2(1, 0x4, 1, &block));
    out
}

/// Every RST_STREAM (stream, error code) in `wire`, a server's frames.
fn resets(wire: &[u8]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 9 <= wire.len() {
        let len = usize::from(wire[i]) << 16 | usize::from(wire[i + 1]) << 8 | usize::from(wire[i + 2]);
        let stream = u32::from_be_bytes([wire[i + 5], wire[i + 6], wire[i + 7], wire[i + 8]]) & 0x7fff_ffff;
        if wire[i + 3] == 3 && len == 4 && i + 13 <= wire.len() {
            out.push((
                stream,
                u32::from_be_bytes([wire[i + 9], wire[i + 10], wire[i + 11], wire[i + 12]]),
            ));
        }
        i += 9 + len;
    }
    out
}

/// RED: a `te` other than `trailers` is reset with HTTP/2 `PROTOCOL_ERROR` before it is a call,
/// as 1.5.5's server (tonic 0.14 over h2 0.4) did; nothing is handed up.
#[test]
fn a_wrong_te_is_reset_protocol_error_and_never_handed_up() {
    let mut a = Conn::accept(posture(), 5 * SEC);
    a.ingest(&opening(Some("gzip")), false);
    a.drive(5 * SEC);
    let wire = a.take_wire(usize::MAX);
    assert_eq!(resets(&wire), vec![(1, 1)], "RST_STREAM PROTOCOL_ERROR on stream 1");
    assert!(a.pieces().is_empty(), "no call reached the host");
}

/// A missing `te` is served, as 1.5.5's server served it: the call is handed up.
#[test]
fn a_missing_te_is_served() {
    let mut a = Conn::accept(posture(), 5 * SEC);
    a.ingest(&opening(None), false);
    a.drive(5 * SEC);
    let wire = a.take_wire(usize::MAX);
    assert!(resets(&wire).is_empty(), "no reset");
    let got: Vec<Piece> = a.pieces().drain(..).collect();
    let h = head(&got, 1);
    assert_eq!(
        h.head.as_ref().map(|w| w.target.as_ref()),
        Some(&b"/pkg.Svc/Say"[..])
    );
    // `te: trailers` is served too, and dropped as hop-by-hop.
    let mut a = Conn::accept(posture(), 5 * SEC);
    a.ingest(&opening(Some("trailers")), false);
    a.drive(5 * SEC);
    let got: Vec<Piece> = a.pieces().drain(..).collect();
    assert_eq!(field(&head(&got, 1).bytes, "te"), None);
}
