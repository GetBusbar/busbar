// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE STREAM, FRAMED BY ITS CLAIM'S FRAMER: a neutral framer under the claim `lp` (each message
//! one length byte, then its bytes; its numbering `0..=9`) frames one accepted stream: body in,
//! messages out; a message in, body out; its close as the closing field block, the final status
//! rendered by the framer alone. RED: a final status past the claim's numbering never crosses.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{
    FramePiece, FramerOut, FramerSink, PIECE_END_OF_FRAME, SIDE_ACCEPT_STREAM,
};

use super::{field_lines, FramedStream};
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor};

#[derive(Default)]
struct Stream {
    inbound: Vec<u8>,
    sides: u32,
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
            name: "lp".into(),
            claims: vec!["web", "lp"],
            // The neutral framer frames its stream over whatever carrier is under it.
            role: busbar_contract::abi::transport::ROLE_FRAMER,
            composes_over: Vec::new(),
            ported: false,
            status_rows: vec![(1, 0, 9)],
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
                        ..Stream::default()
                    },
                );
                o.framing = token;
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
                            _reserved: 0,
                            flags: PIECE_END_OF_FRAME,
                            retry_after_secs: 0,
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
                let block = format!(
                    "lp-status: {}\r\nlp-reason: {}\r\n",
                    i.status,
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
    )
    .expect("open");
    assert_eq!(
        d.framings.lock().unwrap().values().next().map(|s| s.sides),
        Some(SIDE_ACCEPT_STREAM)
    );
    // Body in, messages out, a message split across two reads included.
    assert_eq!(
        s.ingest(b"\x02hi\x03ab", false).unwrap(),
        vec![b"hi".to_vec()]
    );
    assert_eq!(s.ingest(b"c", true).unwrap(), vec![b"abc".to_vec()]);
    // A message in, body out.
    assert_eq!(s.emit(b"yes", true).unwrap(), b"\x03yes".to_vec());
    // The close: the framer renders the unit's status, message and details itself.
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
    let mut s =
        FramedStream::open(Arc::clone(&d) as Arc<dyn FramerDoor>, "lp", "/", &[]).expect("open");
    let refused = s
        .finish(10, b"", b"")
        .expect_err("RED: 10 is not the claim's");
    assert_eq!(refused.outcome, Outcome::Fault);
    assert!(refused.error.contains("finish.final_status"), "{refused:?}");
    assert!(d.finishes.lock().unwrap().is_empty(), "nothing crossed");
    // The stream can still be ended another way.
    let block = s.refuse(b"plane fault", 502).expect("refuse");
    assert_eq!(
        block,
        pairs(&[("lp-status", "502"), ("lp-reason", "plane fault")])
    );
}

#[test]
fn a_claim_the_framer_does_not_answer_opens_no_stream() {
    let d = door();
    assert!(FramedStream::open(d as Arc<dyn FramerDoor>, "other", "/", &[]).is_err());
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
