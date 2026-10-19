// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED (Q128 contract u17 MEDIUM): the slice module ships no policy nothing constructs (Part 1: "A
//! built type or verb with no production construction site is either wired or deleted before the
//! cut"; Part 2 row 84: the contract is shapes only). The slice book, its chain draw and draw
//! verdicts, the overdraft verdict and the pool-scope draw rule had no production caller; the
//! leases the kernel takes stay.

const SLICE: &str = include_str!("../src/slice.rs");

#[test]
fn the_slice_module_ships_no_unconstructed_policy() {
    let words: Vec<&str> = SLICE
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .collect();
    for name in [
        "SliceBook",
        "ChainRefused",
        "Posture",
        "Draw",
        "Overdraft",
        "overdraft",
        "draws_for",
        "bucket_pool",
        "accrues_mid_unit",
    ] {
        assert!(!words.contains(&name), "slice.rs still ships `{name}`");
    }
    for live in [
        "LeaseCell",
        "LeaseSet",
        "ConcurrencyGauge",
        "IN_FLIGHT",
        "takes_lease",
    ] {
        assert!(words.contains(&live), "the live lease `{live}` is kept");
    }
}
