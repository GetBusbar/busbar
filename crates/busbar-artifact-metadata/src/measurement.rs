// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

/// Maximum immutable declarations and cumulative counts per invocation.
pub const MAX_MEASUREMENT_CLASSES: usize = 64;

pub fn valid_name(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= 256
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/'))
}
