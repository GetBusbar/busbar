// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{
    FramePiece, FrameSpan, RendezvousTerms, HANDSHAKE_ANSWERS, LANE_RENDEZVOUS, PIECE_END_OF_FRAME,
    ROLE_FRAMER,
};
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};

pub type Observer = Arc<dyn Fn(&[u8]) + Send + Sync>;

pub struct Recording {
    facts: DoorFacts,
    emitted: Mutex<Vec<Vec<u8>>>,
    observer: Mutex<Option<Observer>>,
    user: Vec<u8>,
    echo: std::sync::atomic::AtomicBool,
    echo_stream: Mutex<Option<u64>>,
    refuse: std::sync::atomic::AtomicBool,
}

impl Recording {
    pub fn new() -> Arc<Self> {
        Self::with_user(b"hostfrag")
    }

    pub fn with_user(user: &[u8]) -> Arc<Self> {
        Arc::new(Self {
            facts: DoorFacts {
                name: "datagram-order".into(),
                claims: vec!["datagram-order"],
                role: ROLE_FRAMER,
                composes_over: Vec::new(),
                ported: false,
                status_rows: Vec::new(),
                duplex: vec!["datagram-order"],
                datagram: true,
            },
            emitted: Mutex::new(Vec::new()),
            observer: Mutex::new(None),
            user: user.to_vec(),
            echo: std::sync::atomic::AtomicBool::new(false),
            echo_stream: Mutex::new(None),
            refuse: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn observe(&self, observer: Observer) {
        *self.observer.lock().unwrap() = Some(observer);
    }

    pub fn emitted(&self) -> Vec<Vec<u8>> {
        self.emitted.lock().unwrap().clone()
    }

    pub fn echo_emits(&self) {
        self.echo.store(true, std::sync::atomic::Ordering::Release);
    }

    pub fn echo_emits_on(&self, stream: u64) {
        *self.echo_stream.lock().unwrap() = Some(stream);
        self.echo_emits();
    }

    pub fn refuse_emits(&self) {
        self.refuse
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

impl FramerDoor for Recording {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Begin(_, out) => out.framing = 7,
            Call::Ingest(input, out) => {
                // SAFETY: DatagramFraming lends its lane for this entire crossing.
                let lane = unsafe { input.lane.as_ref() }.expect("datagram lane");
                if lane.lane == LANE_RENDEZVOUS {
                    let mut used = 0;
                    let mut frame = |bytes: &[u8]| {
                        assert!(used + bytes.len() <= input.sink.frame_cap);
                        // SAFETY: the host's lent buffer is writable through frame_cap bytes;
                        // the checked spans are disjoint and used only within this crossing.
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                bytes.as_ptr(),
                                input.sink.frame.add(used),
                                bytes.len(),
                            );
                        }
                        let span = FrameSpan {
                            offset: used as u64,
                            len: bytes.len() as u64,
                        };
                        used += bytes.len();
                        span
                    };
                    out.datagram.terms = RendezvousTerms {
                        role: HANDSHAKE_ANSWERS,
                        _reserved: 0,
                        local_user: frame(&self.user),
                        local_secret: frame(b"host-password-0123456789"),
                        remote_user: frame(b"farfrag"),
                        remote_secret: frame(b"far-password-0123456789"),
                        peer_fingerprint: frame(&[1; 32]),
                        candidates: FrameSpan::default(),
                    };
                    out.yielded.frame_len = used as u64;
                }
            }
            Call::Emit(input, out) => {
                let bytes = if input.len == 0 {
                    Vec::new()
                } else {
                    // SAFETY: the emit input lends exactly len initialized bytes for this call.
                    unsafe { std::slice::from_raw_parts(input.bytes, input.len) }.to_vec()
                };
                self.emitted.lock().unwrap().push(bytes.clone());
                let observer = self.observer.lock().unwrap().clone();
                if let Some(observer) = observer {
                    observer(&bytes);
                }
                if self.refuse.load(std::sync::atomic::Ordering::Acquire) {
                    return Crossed {
                        outcome: Outcome::Refused,
                        error: None,
                    };
                }
                if self.echo.load(std::sync::atomic::Ordering::Acquire) {
                    let stream = self.echo_stream.lock().unwrap().unwrap_or(input.stream);
                    assert!(bytes.len() <= input.sink.frame_cap && input.sink.pieces_cap > 0);
                    // SAFETY: the lent frame and piece buffers have the checked capacities,
                    // and both writes remain within this Emit crossing.
                    unsafe {
                        if !bytes.is_empty() {
                            std::ptr::copy_nonoverlapping(
                                bytes.as_ptr(),
                                input.sink.frame,
                                bytes.len(),
                            );
                        }
                        input.sink.pieces.write(FramePiece {
                            stream,
                            len: bytes.len() as u64,
                            flags: PIECE_END_OF_FRAME,
                            ..FramePiece::ZERO
                        });
                    }
                    out.yielded.frame_len = bytes.len() as u64;
                    out.yielded.pieces_len = 1;
                }
            }
            _ => {}
        }
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }
}
