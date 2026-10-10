// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared props: a wall clock, and a re-seal for a frame a test edited.

/// The wall clock a test hands a log, in unix milliseconds — the reading the composition root
/// hands a production one. A test may read a clock; the crate under test may not.
pub fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Re-seal a frame whose header fields a test edited — its header check and its digest recomputed
/// over the bytes as they now stand — so the field bounds behind both checks are reached.
pub fn reseal(frame: &mut [u8; crate::record::FRAME_BYTES]) {
    use crate::record::{frame_digest, header_check, DIGEST_OFFSET, HEADER_CHECK_OFFSET};
    let check = header_check(frame);
    frame[HEADER_CHECK_OFFSET..HEADER_CHECK_OFFSET + 4].copy_from_slice(&check);
    let digest = frame_digest(frame);
    frame[DIGEST_OFFSET..DIGEST_OFFSET + 32].copy_from_slice(&digest);
}
