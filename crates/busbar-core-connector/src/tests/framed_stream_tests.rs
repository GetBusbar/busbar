// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE STREAM, FRAMED BY ITS CLAIM'S FRAMER: a neutral framer under the claim `lp` (each message

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{
    FramePiece, FramerOut, FramerSink, PIECE_END_OF_FRAME, SIDE_ACCEPT_STREAM,
};

use busbar_contract::abi::host::service::{SCHEME_PLAIN, SCHEME_SECURE};

use super::{field_lines, FramedStream};
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor};

#[derive(Default)]
struct Stream {
    inbound: Vec<u8>,
    sides: u32,
    scheme: u8,
}

/// One close the framer heard: its status, message and details.
type Finish = (u32, Vec<u8>, Vec<u8>);

/// The neutral framer.
struct LengthDoor {
    facts: DoorFacts,
    framings: Mutex<HashMap<u64, Stream>>,
    next: AtomicU64,
    finishes: Mutex<Vec<Finish>>,
}

fn door() -> Arc<LengthDoor> {
    Arc::new(LengthDoor {
        facts: DoorFacts {
            dials: true,
            name: "lp".into(),
            claims: vec!["web", "lp"],

            role: busbar_contract::abi::transport::ROLE_FRAMER,
            composes_over: Vec::new(),
            ported: false,
            status_rows: vec![(1, 0, 9)],
            status_namespaces: vec![],
            handoff_status: vec![],
            duplex: Vec::new(),
            datagram: false,
        },
        framings: Mutex::new(HashMap::new()),
        next: AtomicU64::new(1),
        finishes: Mutex::new(Vec::new()),
    })
}

fn raw<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: host-lent bytes, valid for the call.
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

fn wire(sink: &FramerSink, o: &mut FramerOut, bytes: &[u8]) {
    assert!(bytes.len() <= sink.wire_cap);
    // SAFETY: the host's wire buffer, bounded above.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), sink.wire, bytes.len()) };
    o.yielded.wire_len = bytes.len() as u64;
}

impl FramerDoor for LengthDoor {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        let ok = Crossed {
            outcome: Outcome::Ready,
            error: None,
        };
        let mut framings = self.framings.lock().unwrap();
        match call {
            Call::Begin(i, o) => {
                let token = self.next.fetch_add(1, Ordering::Relaxed);
                framings.insert(
                    token,
                    Stream {
                        sides: i.side,
                        scheme: i.scheme,
                        ..Stream::default()
                    },
                );
                o.framing = token;
                wire(&i.sink, o, b"trailer: lp-status, lp-message, lp-details, lp-reason\r\nx-open: one\r\nx-open: two\r\n");
                ok
            }
            Call::Ingest(i, o) => {
                let st = framings.get_mut(&i.framing).unwrap();
                st.inbound.extend_from_slice(raw(i.bytes, i.len));
                let (mut at, mut n) = (0usize, 0usize);
                while let Some(&len) = st.inbound.first() {
                    let len = usize::from(len);
                    if st.inbound.len() < 1 + len {
                        break;
                    }
                    let msg: Vec<u8> = st.inbound.drain(..=len).skip(1).collect();
                    // SAFETY: the host's frame and piece buffers; the test's messages fit.
                    unsafe {
                        std::ptr::copy_nonoverlapping(msg.as_ptr(), i.sink.frame.add(at), len);
                        i.sink.pieces.add(n).write(FramePiece {
                            stream: super::STREAM,
                            offset: at as u64,
                            len: len as u64,
                            code: 0,
                            status_class: 0,
                            fault: 0,
                            flags: PIECE_END_OF_FRAME,
                            retry_after_secs: 0,
                            declared_len: 0,
                        });
                    }
                    at += len;
                    n += 1;
                }
                o.yielded.frame_len = at as u64;
                o.yielded.pieces_len = n as u32;
                ok
            }
            Call::Emit(i, o) => {
                let bytes = raw(i.bytes, i.len);
                let mut framed = vec![u8::try_from(bytes.len()).unwrap()];
                framed.extend_from_slice(bytes);
                wire(&i.sink, o, &framed);
                ok
            }
            Call::Refuse(i, o) => {
                let head = if i.head_sent == 0 {
                    format!(":status: 200\r\nlp-status: {}\r\n", i.status)
                } else {
                    format!("lp-status: {}\r\n", i.status)
                };
                let block = format!(
                    "{head}lp-reason: {}\r\n",
                    String::from_utf8_lossy(raw(i.bytes, i.len))
                );
                wire(&i.sink, o, block.as_bytes());
                ok
            }
            Call::Finish(i, o) => {
                let all = raw(i.final_bytes, i.final_bytes_len);
                let at = |s: busbar_contract::abi::mechanism::call::Span| {
                    all[s.offset as usize..(s.offset + s.len) as usize].to_vec()
                };
                let (message, details) = (at(i.final_message), at(i.final_details));
                self.finishes.lock().unwrap().push((
                    i.final_status,
                    message.clone(),
                    details.clone(),
                ));
                let hex: String = details.iter().map(|b| format!("{b:02x}")).collect();
                let block = format!(
                    "lp-status: {}\r\nlp-message: {}\r\nlp-details: {hex}\r\n",
                    i.final_status,
                    String::from_utf8_lossy(&message)
                );
                wire(&i.sink, o, block.as_bytes());
                framings.remove(&i.framing);
                ok
            }
            _ => Crossed {
                outcome: Outcome::Failed,
                error: Some(b"not this framer's op".to_vec()),
            },
        }
    }
}

fn pairs(lines: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    lines
        .iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

#[test]
fn a_stream_is_framed_by_its_claims_framer_and_closed_with_the_units_final_status() {
    let d = door();
    let mut s = FramedStream::open(
        Arc::clone(&d) as Arc<dyn FramerDoor>,
        "lp",
        "/svc/Call",
        &[("x-meta".into(), b"1".to_vec())],
        SCHEME_PLAIN,
    )
    .expect("open");
    assert_eq!(
        d.framings.lock().unwrap().values().next().map(|s| s.sides),
        Some(SIDE_ACCEPT_STREAM)
    );

    assert_eq!(
        s.ingest(b"\x02hi\x03ab", false).unwrap(),
        vec![b"hi".to_vec()]
    );
    assert_eq!(s.ingest(b"c", true).unwrap(), vec![b"abc".to_vec()]);

    assert_eq!(s.emit(b"yes", true).unwrap(), b"\x03yes".to_vec());

    let block = s.finish(5, b"not here", &[0xde, 0xad]).expect("finish");
    assert_eq!(
        block,
        pairs(&[
            ("lp-status", "5"),
            ("lp-message", "not here"),
            ("lp-details", "dead")
        ])
    );
    assert_eq!(
        d.finishes.lock().unwrap().as_slice(),
        &[(5, b"not here".to_vec(), vec![0xde, 0xad])]
    );
}

#[test]
fn a_final_status_past_the_claims_numbering_never_crosses() {
    let d = door();
    let mut s = FramedStream::open(
        Arc::clone(&d) as Arc<dyn FramerDoor>,
        "lp",
        "/",
        &[],
        SCHEME_PLAIN,
    )
    .expect("open");
    let refused = s
        .finish(10, b"", b"")
        .expect_err("RED: 10 is not the claim's");
    assert_eq!(refused.outcome, Outcome::Fault);
    assert!(refused.error.contains("finish.final_status"), "{refused:?}");
    assert!(d.finishes.lock().unwrap().is_empty(), "nothing crossed");

    let block = s.refuse(b"plane fault", 502, false).expect("refuse");
    assert_eq!(
        block,
        pairs(&[
            (":status", "200"),
            ("lp-status", "502"),
            ("lp-reason", "plane fault")
        ])
    );
}

/// A refusal after the stream's response head went out is told so, and its block is closing lines
#[test]
fn a_refusal_after_the_head_is_told_the_head_went_out() {
    for head_sent in [false, true] {
        let d = door();
        let mut s = FramedStream::open(
            Arc::clone(&d) as Arc<dyn FramerDoor>,
            "lp",
            "/",
            &[],
            SCHEME_PLAIN,
        )
        .expect("open");
        let block = s.refuse(b"cut", 4, head_sent).expect("refuse");
        let has_head = block.iter().any(|(name, _)| name.as_slice() == b":status");
        assert_eq!(has_head, !head_sent, "head_sent={head_sent}: {block:?}");
    }
}

#[test]
fn a_claim_the_framer_does_not_answer_opens_no_stream() {
    let d = door();
    assert!(FramedStream::open(d as Arc<dyn FramerDoor>, "other", "/", &[], SCHEME_PLAIN).is_err());
}

#[test]
fn a_stream_retains_its_framers_initial_fields_including_repeated_values() {
    let stream = FramedStream::open(door(), "lp", "/", &[], SCHEME_PLAIN).unwrap();
    assert_eq!(
        stream.opening_fields(),
        pairs(&[
            ("trailer", "lp-status, lp-message, lp-details, lp-reason"),
            ("x-open", "one"),
            ("x-open", "two"),
        ])
    );
}

#[test]
fn malformed_initial_field_blocks_are_refused_whole() {
    for block in [
        b"trailer: lp-status\r\ncut".as_slice(),
        b":status: 200\r\n",
        b"bad name: x\r\n",
        b"x: bad\0value\r\n",
        b"x: bare\nvalue\r\n",
    ] {
        assert!(super::opening_fields(block).is_err(), "{block:?}");
    }
}

#[test]
fn field_lines_read_a_closing_block_in_order() {
    assert_eq!(
        field_lines(b"a: 1\r\nb:2 \r\n\r\n").unwrap(),
        pairs(&[("a", "1"), ("b", "2")])
    );
    assert_eq!(
        field_lines(b":status: 200\r\nc: 3\r\n").unwrap(),
        pairs(&[(":status", "200"), ("c", "3")])
    );
    assert!(field_lines(b"no colon\r\n").is_err());
    assert!(field_lines(b":: pseudo with no name\r\n").is_err());
    assert!(field_lines(b": empty name\r\n").is_err());
}

/// A stream begins with its listener's scheme: SECURE where the connector terminated connection
#[test]
fn a_stream_begins_with_its_listeners_scheme() {
    for scheme in [SCHEME_SECURE, SCHEME_PLAIN] {
        let d = door();
        let _s = FramedStream::open(
            Arc::clone(&d) as Arc<dyn FramerDoor>,
            "lp",
            "/",
            &[],
            scheme,
        )
        .expect("open");
        assert_eq!(
            d.framings.lock().unwrap().values().next().map(|s| s.scheme),
            Some(scheme)
        );
    }
}

#[test]
fn neutral_closing_uses_producer_metadata_and_preserves_an_unknown_namespace() {
    struct MetadataDoor {
        inner: Arc<LengthDoor>,
        facts: DoorFacts,
    }
    impl FramerDoor for MetadataDoor {
        fn facts(&self) -> &DoorFacts {
            &self.facts
        }
        fn cross(&self, call: Call<'_>) -> Crossed {
            match call {
                Call::Refuse(input, output) => {
                    wire(&input.sink, output, b"opaque field: opaque value\r\n");
                    assert!(input.sink.pieces_cap > 0);
                    // SAFETY: the host lends one writable frame slot, checked above.
                    unsafe {
                        *input.sink.pieces = FramePiece {
                            stream: input.stream,
                            offset: 0,
                            len: 0,
                            code: 70_123,
                            status_class: busbar_contract::abi::transport::STATUS_SUCCESS,
                            flags: busbar_contract::abi::transport::PIECE_FIELDS
                                | busbar_contract::abi::transport::PIECE_HAS_CODE
                                | busbar_contract::abi::transport::PIECE_CODE_HANDOFF
                                | PIECE_END_OF_FRAME,
                            fault: busbar_contract::abi::transport::FAULT_NONE,
                            retry_after_secs: 0,
                            declared_len: 0,
                        };
                    }
                    output.yielded.pieces_len = 1;
                    Crossed {
                        outcome: Outcome::Ready,
                        error: None,
                    }
                }
                other => self.inner.cross(other),
            }
        }
    }
    let inner = door();
    let mut facts = inner.facts.clone();
    facts.handoff_status = vec![None, Some(Arc::from("quartz-opening-v7"))];
    let door: Arc<dyn FramerDoor> = Arc::new(MetadataDoor { inner, facts });
    let mut stream =
        FramedStream::open_neutral(door, "lp", "opaque target", &[], SCHEME_PLAIN).unwrap();
    let closing = stream.refuse_response(&[], 503, false).unwrap();
    assert_eq!(
        closing.status,
        Some(70_123),
        "no HTTP status range restriction"
    );
    assert_eq!(
        closing.status_namespace.as_deref(),
        Some("quartz-opening-v7")
    );
    assert_eq!(closing.fields, pairs(&[("opaque field", "opaque value")]));
}

struct TimedDoor {
    inner: Arc<LengthDoor>,
    fail_emit: bool,
    fail_begin: bool,
}

impl FramerDoor for TimedDoor {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        use busbar_contract::abi::transport::{PIECE_END, PIECE_STREAM_FAILED, YIELD_HAS_DEADLINE};
        let fail = |sink: &FramerSink, output: &mut FramerOut| {
            // SAFETY: the host lends a writable piece slot for this framing call.
            unsafe {
                sink.pieces.write(FramePiece {
                    stream: super::STREAM,
                    offset: 0,
                    len: 0,
                    code: 0,
                    status_class: 0,
                    fault: 0,
                    flags: PIECE_STREAM_FAILED | PIECE_END,
                    retry_after_secs: 0,
                    declared_len: 0,
                });
            }
            output.yielded.pieces_len = 1;
            Crossed {
                outcome: Outcome::Ready,
                error: None,
            }
        };
        match call {
            Call::Begin(input, output) => {
                let crossed = self.inner.cross(Call::Begin(input, output));
                if self.fail_begin {
                    return fail(&input.sink, output);
                }
                output.yielded.flags |= YIELD_HAS_DEADLINE;
                output.yielded.next_deadline_ns = input.sink.now_monotonic_ns + 1_000_000_000;
                crossed
            }
            Call::Ingest(input, output) => {
                let crossed = self.inner.cross(Call::Ingest(input, output));
                output.yielded.flags |= YIELD_HAS_DEADLINE;
                output.yielded.next_deadline_ns = input.sink.now_monotonic_ns + 2_000_000_000;
                crossed
            }
            Call::Timer(input, output) => fail(&input.sink, output),
            Call::Emit(input, output) if self.fail_emit => fail(&input.sink, output),
            other => self.inner.cross(other),
        }
    }
}

#[test]
fn accepted_stream_retains_replaces_and_clears_its_framers_deadline() {
    let door = Arc::new(TimedDoor {
        inner: door(),
        fail_emit: false,
        fail_begin: false,
    });
    let mut stream = FramedStream::open(door, "lp", "/", &[], SCHEME_PLAIN).unwrap();
    let opened = stream
        .deadline()
        .expect("Begin's deadline must be scheduled");
    stream.ingest(b"\x01q", true).unwrap();
    assert!(
        stream.deadline().unwrap() > opened,
        "Ingest replaces the timer"
    );
    assert_eq!(stream.timer().unwrap_err().outcome, Outcome::Failed);
    assert!(
        stream.deadline().is_none(),
        "the terminal yield clears its timer"
    );
}

#[test]
fn accepted_stream_emit_failure_is_not_an_empty_success() {
    let door = Arc::new(TimedDoor {
        inner: door(),
        fail_emit: true,
        fail_begin: false,
    });
    let mut stream = FramedStream::open(door, "lp", "/", &[], SCHEME_PLAIN).unwrap();
    assert_eq!(
        stream.emit(b"late", true).unwrap_err().outcome,
        Outcome::Failed
    );
}

#[test]
fn accepted_stream_begin_failure_never_admits_a_unit() {
    let door = Arc::new(TimedDoor {
        inner: door(),
        fail_emit: false,
        fail_begin: true,
    });
    assert_eq!(
        FramedStream::open(door, "lp", "/", &[], SCHEME_PLAIN)
            .unwrap_err()
            .outcome,
        Outcome::Failed
    );
}
