// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicU64, Ordering};

pub(super) fn next(counter: &AtomicU64) -> u64 {
    counter.fetch_add(1, Ordering::Relaxed)
}

pub(super) fn seed() -> u64 {
    let mut buf = [0u8; 8];
    match getrandom::fill(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf),
        Err(_) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_counter_is_unique_and_monotonic_across_sequential_requests() {
        let counter = AtomicU64::new(seed());
        let a = next(&counter);
        let b = next(&counter);
        let c = next(&counter);
        assert!(b > a, "the counter must strictly increase: {a} then {b}");
        assert!(c > b, "the counter must strictly increase: {b} then {c}");
        assert_eq!(b, a + 1, "a plain fetch_add(1): no gaps between requests");
        assert_eq!(c, a + 2);
        let second = AtomicU64::new(seed());
        let d = next(&second);
        assert_ne!(
            d, a,
            "two independently-seeded counters must not coincide (boot entropy seed)"
        );
    }
}
