// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Finite, distinct LINE feedback through real datagram framing. Only this fixture writes the
//! ABI loans; it never retains their pointers or reads spare or freed allocation bytes.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{
    FramePiece, FrameSpan, FramerOut, FramerSink, RendezvousTerms, HANDSHAKE_ANSWERS,
    LANE_RENDEZVOUS, PIECE_END_OF_FRAME, PIECE_FIELDS, ROLE_FRAMER, YIELD_MORE,
};
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};

/// Optional terminal output stresses independent deep copies and empty-piece metadata.
#[derive(Clone, Copy, Default)]
pub enum Terminals {
    /// Each depth-zero token yields its complete path once.
    #[default]
    Paths,
    /// Two pieces overlap the same initialized payload span, followed by empty messages.
    OverlapAndEmpty {
        payload_bytes: usize,
        empty_pieces: usize,
    },
}

struct Piece {
    stream: u64,
    bytes: Vec<u8>,
    fields: bool,
}

#[derive(Default)]
struct State {
    pending: VecDeque<Piece>,
    emitted: Vec<Vec<u8>>,
    recalls: usize,
    settled: bool,
}

/// A valid association: positive depth branches into distinct zero/one children on its LINE;
/// zero depth publishes the token's path on its own CHANNEL. Two instances form finite feedback.
pub struct Branching {
    facts: DoorFacts,
    line: u64,
    channel: u64,
    user: Vec<u8>,
    per_batch: usize,
    terminals: Terminals,
    state: Mutex<State>,
    finished: AtomicUsize,
    consume_only: AtomicBool,
}

impl Branching {
    /// An independently identified association. With `per_batch=1`, use tokens over half the
    /// frame loan so a second child genuinely needs a same-operation recall.
    pub fn new(
        line: u64,
        channel: u64,
        user: &[u8],
        per_batch: usize,
        terminals: Terminals,
    ) -> Arc<Self> {
        assert!(per_batch > 0);
        Arc::new(Self {
            facts: DoorFacts {
                name: "datagram-feedback".into(),
                claims: vec!["datagram-feedback"],
                role: ROLE_FRAMER,
                composes_over: Vec::new(),
                ported: false,
                status_rows: Vec::new(),
                duplex: vec!["datagram-feedback"],
                datagram: true,
            },
            line,
            channel,
            user: user.to_vec(),
            per_batch,
            terminals,
            state: Mutex::new(State::default()),
            finished: AtomicUsize::new(0),
            consume_only: AtomicBool::new(false),
        })
    }

    /// Fresh Emit inputs, copied only while their initialized input loan is live.
    pub fn emitted(&self) -> Vec<Vec<u8>> {
        self.state.lock().unwrap().emitted.clone()
    }

    /// Empty-input recalls that drained the preceding Emit's remaining output.
    pub fn recalls(&self) -> usize {
        self.state.lock().unwrap().recalls
    }

    /// Actual Finish crossings, including cancellation and destruction.
    pub fn finishes(&self) -> usize {
        self.finished.load(Ordering::SeqCst)
    }

    /// Have subsequent fresh Emits accept and record their complete input without new output.
    /// An already owed operation must finish before a fresh inert input can cross.
    pub fn consume_without_output(&self) {
        self.consume_only.store(true, Ordering::Release);
    }

    fn enqueue(&self, state: &mut State, bytes: &[u8]) {
        let (&depth, path) = bytes.split_first().expect("a fresh token has depth");
        if depth == 0 {
            state.pending.push_back(Piece {
                stream: self.channel,
                bytes: path.to_vec(),
                fields: false,
            });
        } else {
            for bit in [0, 1] {
                let mut child = Vec::with_capacity(bytes.len() + 1);
                child.push(depth - 1);
                child.extend_from_slice(path);
                child.push(bit);
                state.pending.push_back(Piece {
                    stream: self.line,
                    bytes: child,
                    fields: false,
                });
            }
        }
    }
}

fn append(frame: &mut Vec<u8>, bytes: &[u8]) -> FrameSpan {
    let span = FrameSpan {
        offset: frame.len() as u64,
        len: bytes.len() as u64,
    };
    frame.extend_from_slice(bytes);
    span
}

fn write(sink: &FramerSink, out: &mut FramerOut, frame: &[u8], pieces: &[FramePiece]) {
    assert!(frame.len() <= sink.frame_cap && pieces.len() <= sink.pieces_cap);
    // SAFETY: both loans are writable for their checked capacities during this crossing.
    // Only initialized source bytes and complete initialized descriptors are copied.
    unsafe {
        if !frame.is_empty() {
            std::ptr::copy_nonoverlapping(frame.as_ptr(), sink.frame, frame.len());
        }
        if !pieces.is_empty() {
            std::ptr::copy_nonoverlapping(pieces.as_ptr(), sink.pieces, pieces.len());
        }
    }
    out.yielded.frame_len = frame.len() as u64;
    out.yielded.pieces_len = pieces.len() as u32;
}

impl FramerDoor for Branching {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Begin(_, out) => out.framing = self.line,
            Call::Ingest(input, out) => {
                // SAFETY: the host lends its datagram lane for the complete call.
                let lane = unsafe { input.lane.as_ref() }.expect("datagram lane");
                let mut state = self.state.lock().unwrap();
                if lane.lane == LANE_RENDEZVOUS && !state.settled {
                    state.settled = true;
                    let mut frame = Vec::new();
                    out.datagram.terms = RendezvousTerms {
                        role: HANDSHAKE_ANSWERS,
                        _reserved: 0,
                        local_user: append(&mut frame, &self.user),
                        local_secret: append(&mut frame, b"host-password-0123456789"),
                        remote_user: append(&mut frame, b"farfrag"),
                        remote_secret: append(&mut frame, b"far-password-0123456789"),
                        peer_fingerprint: append(&mut frame, &[1; 32]),
                        candidates: FrameSpan::default(),
                    };
                    let pieces: Vec<_> = [
                        (self.line, b"kind: feedback\r\n".as_slice()),
                        (self.channel, b"label: messages\r\n".as_slice()),
                    ]
                    .into_iter()
                    .map(|(stream, bytes)| {
                        let span = append(&mut frame, bytes);
                        FramePiece {
                            stream,
                            offset: span.offset,
                            len: span.len,
                            flags: PIECE_FIELDS | PIECE_END_OF_FRAME,
                            ..FramePiece::ZERO
                        }
                    })
                    .collect();
                    write(&input.sink, out, &frame, &pieces);
                }
            }
            Call::Emit(input, out) => {
                let mut state = self.state.lock().unwrap();
                let bytes = if input.len == 0 {
                    &[][..]
                } else {
                    // SAFETY: exactly these initialized bytes are lent for this Emit.
                    unsafe { std::slice::from_raw_parts(input.bytes, input.len) }
                };
                if bytes.is_empty() {
                    assert!(
                        !state.pending.is_empty(),
                        "recall must drain an owed operation"
                    );
                    assert_eq!(input.end_of_frame, 0);
                    assert_eq!(input.flags & busbar_contract::abi::transport::EMIT_TEXT, 0);
                    state.recalls += 1;
                } else {
                    assert!(
                        state.pending.is_empty(),
                        "fresh input cannot overtake same-op MORE"
                    );
                    state.emitted.push(bytes.to_vec());
                    if self.consume_only.load(Ordering::Acquire) {
                        return Crossed {
                            outcome: Outcome::Ready,
                            error: None,
                        };
                    }
                    if let Terminals::OverlapAndEmpty {
                        payload_bytes,
                        empty_pieces,
                    } = self.terminals
                    {
                        if bytes[0] == 0 {
                            assert!(payload_bytes <= input.sink.frame_cap);
                            assert!(empty_pieces + 2 <= input.sink.pieces_cap);
                            let frame = vec![b'x'; payload_bytes];
                            let mut pieces = vec![
                                FramePiece {
                                    stream: self.channel,
                                    len: payload_bytes as u64,
                                    flags: PIECE_END_OF_FRAME,
                                    ..FramePiece::ZERO
                                };
                                2
                            ];
                            pieces.extend((0..empty_pieces).map(|_| FramePiece {
                                stream: self.channel,
                                flags: PIECE_END_OF_FRAME,
                                ..FramePiece::ZERO
                            }));
                            write(&input.sink, out, &frame, &pieces);
                            return Crossed {
                                outcome: Outcome::Ready,
                                error: None,
                            };
                        }
                    }
                    self.enqueue(&mut state, bytes);
                }
                let mut frame = Vec::new();
                let mut pieces = Vec::new();
                while pieces.len() < self.per_batch.min(input.sink.pieces_cap) {
                    let Some(piece) = state.pending.front() else {
                        break;
                    };
                    if frame.len() + piece.bytes.len() > input.sink.frame_cap {
                        break;
                    }
                    let span = append(&mut frame, &piece.bytes);
                    pieces.push(FramePiece {
                        stream: piece.stream,
                        offset: span.offset,
                        len: span.len,
                        flags: PIECE_END_OF_FRAME | if piece.fields { PIECE_FIELDS } else { 0 },
                        ..FramePiece::ZERO
                    });
                    state.pending.pop_front();
                }
                assert!(
                    !pieces.is_empty(),
                    "fixture token fits at least one host loan"
                );
                if self.per_batch == 1 {
                    if let Some(next) = state.pending.front() {
                        assert!(
                            frame.len() + next.bytes.len() > input.sink.frame_cap,
                            "MORE control must fill the actual loan before deferring a child"
                        );
                    }
                }
                write(&input.sink, out, &frame, &pieces);
                if !state.pending.is_empty() {
                    out.yielded.flags = YIELD_MORE;
                }
            }
            Call::Finish(..) => {
                self.finished.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }
}
