// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SPOOL'S FRAMING (MONEY-DESIGN §3c, "Framing"): every record is `len (u32 LE) ++ crc32c
//! (u32 LE) ++ body`. A reader stops at the first frame that is short or whose checksum does not
//! match: that is a torn tail, and no END was released for it, because ENDs are released only after
//! the round's `fsync`.

/// The frame header: the body length, then its CRC32C.
pub const HEADER: usize = 8;

/// The largest body a frame may carry. A longer length field is damage, never a record.
pub const MAX_BODY: usize = 64 * 1024 * 1024;

/// CRC32C (Castagnoli, reflected polynomial `0x82F63B78`), table-driven.
#[must_use]
pub fn crc32c(bytes: &[u8]) -> u32 {
    static TABLE: std::sync::LazyLock<[u32; 256]> = std::sync::LazyLock::new(|| {
        let mut table = [0u32; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 == 1 {
                    0x82F6_3B78 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        table
    });
    let mut crc = !0u32;
    for b in bytes {
        crc = TABLE[((crc ^ u32::from(*b)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// `body` framed onto `out`.
pub fn put(out: &mut Vec<u8>, body: &[u8]) {
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&crc32c(body).to_le_bytes());
    out.extend_from_slice(body);
}

/// Every whole, verified frame body in `bytes`, in order, and the offset just past the last one.
/// Whatever follows that offset is a torn or damaged tail.
#[must_use]
pub fn read_all(bytes: &[u8]) -> (Vec<&[u8]>, usize) {
    let mut at = 0usize;
    let mut out = Vec::new();
    while let Some(head) = bytes.get(at..at + HEADER) {
        let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
        let crc = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
        if len > MAX_BODY {
            break;
        }
        let Some(body) = bytes.get(at + HEADER..at + HEADER + len) else {
            break;
        };
        if crc32c(body) != crc {
            break;
        }
        out.push(body);
        at += HEADER + len;
    }
    (out, at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_matches_the_published_check_value() {
        // RFC 3720 B.4 / the CRC catalogue's check value for "123456789".
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn a_torn_tail_at_every_offset_reads_as_the_longest_whole_prefix() {
        let mut bytes = Vec::new();
        let bodies: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 3 + i as usize]).collect();
        let mut ends = vec![0usize];
        for b in &bodies {
            put(&mut bytes, b);
            ends.push(bytes.len());
        }
        for cut in 0..=bytes.len() {
            let (read, end) = read_all(&bytes[..cut]);
            let whole = ends.iter().rposition(|e| *e <= cut).unwrap_or(0);
            assert_eq!(read.len(), whole, "cut at {cut}");
            assert_eq!(end, ends[whole]);
            for (r, b) in read.iter().zip(&bodies) {
                assert_eq!(*r, b.as_slice());
            }
        }
    }

    #[test]
    fn a_flipped_byte_ends_the_read_at_its_frame() {
        let mut bytes = Vec::new();
        put(&mut bytes, b"first");
        let second = bytes.len();
        put(&mut bytes, b"second");
        put(&mut bytes, b"third");
        bytes[second + HEADER + 1] ^= 0x40;
        let (read, end) = read_all(&bytes);
        assert_eq!(read, vec![b"first".as_slice()]);
        assert_eq!(end, second);
    }
}
