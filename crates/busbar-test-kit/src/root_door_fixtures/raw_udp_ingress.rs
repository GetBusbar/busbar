// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real clear-lane ingress with valid rendezvous terms, using only live ABI loans.

use std::sync::{Arc, Mutex};

use busbar_contract::abi::transport::{FramePiece, LANE_CLEAR, PIECE_END_OF_FRAME};
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};

use super::datagram_order::Recording;

/// An accepting association that records raw input and yields media on its selected stream.
pub struct Ingress {
    recording: Arc<Recording>,
    received: Mutex<Vec<Vec<u8>>>,
    stream: u64,
}

impl Ingress {
    /// Distinct credentials allow several real associations to share a host socket.
    pub fn new(user: &[u8], stream: u64) -> Arc<Self> {
        Arc::new(Self {
            recording: Recording::with_user(user),
            received: Mutex::new(Vec::new()),
            stream,
        })
    }

    /// The existing fixture's Emit recording and park observer.
    pub fn recording(&self) -> &Arc<Recording> {
        &self.recording
    }

    /// Initialized input copied during each real clear-lane crossing.
    pub fn received(&self) -> Vec<Vec<u8>> {
        self.received.lock().unwrap().clone()
    }
}

impl FramerDoor for Ingress {
    fn facts(&self) -> &DoorFacts {
        self.recording.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        if let Call::Ingest(input, out) = call {
            // SAFETY: the connector lends the lane and initialized input for this crossing.
            let lane = unsafe { input.lane.as_ref() }.expect("datagram lane");
            if lane.lane == LANE_CLEAR {
                let bytes = if input.len == 0 {
                    &[][..]
                } else {
                    // SAFETY: these exact initialized bytes remain lent until this call returns.
                    unsafe { std::slice::from_raw_parts(input.bytes, input.len) }
                };
                self.received.lock().unwrap().push(bytes.to_vec());
                // A verified check establishes the source path; media exercises real output.
                if bytes.first().is_some_and(|b| (128..=191).contains(b)) {
                    assert!(bytes.len() <= input.sink.frame_cap && input.sink.pieces_cap > 0);
                    // SAFETY: both output loans have the checked capacities for these writes.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            input.sink.frame,
                            bytes.len(),
                        );
                        input.sink.pieces.write(FramePiece {
                            stream: self.stream,
                            len: bytes.len() as u64,
                            flags: PIECE_END_OF_FRAME,
                            ..FramePiece::ZERO
                        });
                    }
                    out.yielded.frame_len = bytes.len() as u64;
                    out.yielded.pieces_len = 1;
                }
                return Crossed {
                    outcome: busbar_contract::abi::mechanism::call::Outcome::Ready,
                    error: None,
                };
            }
            return self.recording.cross(Call::Ingest(input, out));
        }
        self.recording.cross(call)
    }
}

/// An authenticated check under the matching fixture's local credentials.
pub fn check(user: &str, transaction: u8) -> Vec<u8> {
    let username = format!("{user}:farfrag").into_bytes();
    let padded = username.len().div_ceil(4) * 4;
    let mut bytes = vec![0x00, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42];
    bytes.extend_from_slice(&[transaction; 12]);
    bytes.extend_from_slice(&0x0006_u16.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(username.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&username);
    bytes.resize(20 + 4 + padded, 0);
    let covered = u16::try_from(bytes.len() - 20 + 24).unwrap();
    bytes[2..4].copy_from_slice(&covered.to_be_bytes());
    let key = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        b"host-password-0123456789",
    );
    let integrity = ring::hmac::sign(&key, &bytes);
    bytes.extend_from_slice(&0x0008_u16.to_be_bytes());
    bytes.extend_from_slice(&20_u16.to_be_bytes());
    bytes.extend_from_slice(integrity.as_ref());
    bytes
}
