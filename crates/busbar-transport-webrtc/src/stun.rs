// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The few facts of a connectivity check the framer reads itself (RFC 8489 framing, RFC 8445
//! attributes): its class, its transaction id and whether it nominates. Integrity is the media
//! stack's ICE agent's to judge (it answers only a check whose MESSAGE-INTEGRITY verifies), and the
//! host's, independently; this module judges nothing.

/// The STUN magic cookie.
const MAGIC: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
/// Binding request.
const BINDING_REQUEST: u16 = 0x0001;
/// Binding success response.
const BINDING_SUCCESS: u16 = 0x0101;
/// USE-CANDIDATE (RFC 8445 §16.1).
const USE_CANDIDATE: u16 = 0x0025;

/// What a datagram is, as far as nomination goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// A Binding request; `nominates` = it carries USE-CANDIDATE.
    Request {
        /// The transaction id.
        txid: [u8; 12],
        /// It nominates the pair it travels on.
        nominates: bool,
    },
    /// A Binding success response.
    Success {
        /// The transaction id.
        txid: [u8; 12],
    },
}

/// Read `datagram` as a Binding request or success response; `None` for anything else.
#[must_use]
pub fn read(datagram: &[u8]) -> Option<Check> {
    let head = datagram.get(..20)?;
    if head[0] & 0xC0 != 0 || head[4..8] != MAGIC {
        return None;
    }
    let kind = u16::from_be_bytes([head[0], head[1]]);
    let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
    let body = datagram.get(20..20 + len)?;
    let mut txid = [0_u8; 12];
    txid.copy_from_slice(&head[8..20]);
    match kind {
        BINDING_REQUEST => Some(Check::Request {
            txid,
            nominates: attributes(body).any(|t| t == USE_CANDIDATE),
        }),
        BINDING_SUCCESS => Some(Check::Success { txid }),
        _ => None,
    }
}

/// The attribute types of a STUN body, in order, stopping at the first malformed one.
fn attributes(body: &[u8]) -> impl Iterator<Item = u16> + '_ {
    let mut at = 0_usize;
    std::iter::from_fn(move || {
        let h = body.get(at..at + 4)?;
        let t = u16::from_be_bytes([h[0], h[1]]);
        let len = usize::from(u16::from_be_bytes([h[2], h[3]]));
        let padded = len.checked_add(3)? & !3;
        at = at.checked_add(4)?.checked_add(padded)?;
        if at > body.len() {
            return None;
        }
        Some(t)
    })
}

/// Whether `datagram` is a STUN message at all (RFC 7983: first byte 0..=3).
#[must_use]
pub fn is_stun(datagram: &[u8]) -> bool {
    matches!(datagram.first(), Some(0..=3))
}
