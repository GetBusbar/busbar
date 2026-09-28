// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S OWN CRC-32 (#83a O10: no reviewed-list addition; the need is removed instead): the
//! CRC-32/ISO-HDLC checksum the AWS event-stream framing stamps on every prelude and message — the
//! reflected polynomial `0xEDB88320`, initial value and final XOR `0xFFFFFFFF`. A 256-entry table
//! built at compile time and one table step per byte. The frames it covers are single stream events
//! (a few hundred bytes), so the byte-at-a-time loop is not on a measurable path.
//!
//! The standard check vectors are pinned beside this module, and the event-stream drift test holds
//! every frame this plane encodes byte-identical to the host's encoder.

/// The reflected CRC-32 polynomial.
const POLY: u32 = 0xEDB8_8320;

/// One table entry per byte value: the CRC of that byte alone, before the final XOR.
const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// The CRC-32 of `bytes`.
#[must_use]
pub fn hash(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in bytes {
        crc = TABLE[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
#[path = "tests/crc32_tests.rs"]
mod tests;
