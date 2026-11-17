// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bounded network facts retained before a store exists and for the lifetime of boot leases.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_prefix_has_explicit_overflow_and_remains_writable_after_drain() {
        let observations = Observations::default();
        for _ in 0..CAPACITY + 3 {
            observations.record(
                "https://user:password@secret.example/path?token=value",
                Some(7),
                Some(2),
                Outcome::Tls,
            );
        }
        let batch = observations.drain();
        assert_eq!(batch.facts.len(), CAPACITY);
        assert_eq!(batch.overflow, 3);
        assert!(batch.facts.iter().all(|fact| fact.host == "secret.example"));
        observations.record("late.example", Some(7), Some(2), Outcome::Delegated);
        let late = observations.drain();
        assert_eq!(late.facts.len(), 1);
        assert_eq!(late.overflow, 0);
    }
}
