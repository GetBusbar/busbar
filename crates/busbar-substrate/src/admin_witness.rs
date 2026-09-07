// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROCESS-WIDE ADMIN-ERROR WITNESS LEDGER — a neutral, single-copy home for the taxonomy-drift
//! audit's record of "which (operation, error-kind, condition) an admin response has actually
//! produced".
//!
//! ## Why it lives here and not in `busbar-core`
//!
//! `busbar-core`'s own test binary links `busbar-core` TWICE: once as the crate-under-test
//! (`cfg(test)`) and once as an ordinary dependency of the extracted plane crates (`busbar-mcp` /
//! `busbar-a2a`), whose admin-verb drivers drive requests through THAT copy's recording layer. A
//! `static` witness set in `busbar-core` would therefore split in two — the plane emissions landing
//! in the dependency copy, the audit reading the test copy — and the cross-plane over-claim check
//! would report every plane trust-verb response as un-witnessed. `busbar-substrate` is a plain
//! dependency of all three crates, compiled ONCE with feature unification, so a witness ledger here is
//! the one both copies of `busbar-core` reach. The keys are NEUTRAL strings (the operation's relative
//! path, the HTTP method, the error kind, an optional condition) precisely so this crate names none of
//! `busbar-core`'s taxonomy enums.

use std::collections::BTreeSet;
use std::sync::Mutex;

/// One witnessed emission as neutral strings: `(rel, method, kind, cond)`.
pub type Witness = (String, String, String, Option<String>);

static WITNESSED: Mutex<BTreeSet<Witness>> = Mutex::new(BTreeSet::new());

/// Record one observed admin-error emission. Called from `busbar-core`'s recording layer in EITHER
/// copy of the crate; both reach this one ledger.
pub fn record(rel: &str, method: &str, kind: &str, cond: Option<&str>) {
    if let Ok(mut set) = WITNESSED.lock() {
        set.insert((
            rel.to_string(),
            method.to_string(),
            kind.to_string(),
            cond.map(str::to_string),
        ));
    }
}

/// Every emission the process has witnessed so far, across both copies of `busbar-core`.
pub fn snapshot() -> BTreeSet<Witness> {
    WITNESSED.lock().map(|s| s.clone()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // `WITNESSED` is one process-wide static that every test in this binary shares, so each test
    // below records under a `rel` unique to itself (a `#[test]`-fn-local literal no other test in
    // this file or crate uses) and asserts only "this exact tuple is present in the snapshot" rather
    // than asserting anything about the snapshot's total size — the one assertion shape that stays
    // correct under `cargo test`'s default parallel, shared-process execution.

    #[test]
    fn record_then_snapshot_contains_the_witnessed_tuple_verbatim() {
        record(
            "admin-witness-test/verbatim",
            "POST",
            "NotFound",
            Some("cond-a"),
        );
        let snap = snapshot();
        assert!(
            snap.contains(&(
                "admin-witness-test/verbatim".to_string(),
                "POST".to_string(),
                "NotFound".to_string(),
                Some("cond-a".to_string()),
            )),
            "the exact recorded tuple must be readable back out of the snapshot"
        );
    }

    #[test]
    fn a_missing_condition_records_and_reads_back_as_none_not_a_sentinel_string() {
        record("admin-witness-test/no-cond", "GET", "Forbidden", None);
        let snap = snapshot();
        assert!(
            snap.contains(&(
                "admin-witness-test/no-cond".to_string(),
                "GET".to_string(),
                "Forbidden".to_string(),
                None,
            )),
            "a `None` condition must round-trip as `None`, not e.g. an empty-string stand-in"
        );
    }

    #[test]
    fn recording_the_same_tuple_twice_is_idempotent_in_the_set() {
        for _ in 0..3 {
            record("admin-witness-test/dedup", "PUT", "Conflict", Some("x"));
        }
        let snap = snapshot();
        let matches = snap
            .iter()
            .filter(|(rel, method, kind, cond)| {
                rel == "admin-witness-test/dedup"
                    && method == "PUT"
                    && kind == "Conflict"
                    && cond.as_deref() == Some("x")
            })
            .count();
        assert_eq!(
            matches, 1,
            "a `BTreeSet` must hold one copy of an identical tuple no matter how many times it is recorded"
        );
    }

    #[test]
    fn distinct_fields_are_distinct_witnesses_not_folded_together() {
        record("admin-witness-test/distinct", "GET", "kind-a", None);
        record("admin-witness-test/distinct", "GET", "kind-b", None);
        let snap = snapshot();
        assert!(snap.contains(&(
            "admin-witness-test/distinct".to_string(),
            "GET".to_string(),
            "kind-a".to_string(),
            None,
        )));
        assert!(snap.contains(&(
            "admin-witness-test/distinct".to_string(),
            "GET".to_string(),
            "kind-b".to_string(),
            None,
        )));
    }
}
