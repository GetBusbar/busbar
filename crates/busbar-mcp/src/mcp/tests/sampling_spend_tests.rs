// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-UPSTREAM SAMPLING BUDGET, in isolation: a counter that refuses at the cap, resets on
//! the minute, and never lets one server's spend bite another's.

use super::SamplingSpend;

#[test]
fn the_cap_admits_exactly_cap_completions_in_one_window_and_refuses_the_next() {
    let spend = SamplingSpend::new();
    let now = 1_000_000;
    for _ in 0..3 {
        spend
            .try_spend("fs", 3, now)
            .expect("under the cap, the spend is admitted");
    }
    let err = spend
        .try_spend("fs", 3, now)
        .expect_err("the cap is a refusal, not a warning");
    assert!(
        err.contains("tools.fs.sampling.max_requests_per_minute"),
        "the refusal names the exact key an operator would raise: {err}"
    );
}

#[test]
fn the_window_resets_on_the_next_minute() {
    let spend = SamplingSpend::new();
    let now = 1_000_000;
    spend
        .try_spend("fs", 1, now)
        .expect("the first is admitted");
    spend
        .try_spend("fs", 1, now)
        .expect_err("the second in the same minute is refused");
    spend
        .try_spend("fs", 1, now + 60)
        .expect("the budget is per minute, and the next minute is a fresh window");
}

#[test]
fn one_servers_spend_does_not_bite_anothers() {
    let spend = SamplingSpend::new();
    let now = 1_000_000;
    spend.try_spend("fs", 1, now).expect("fs spends its budget");
    spend.try_spend("fs", 1, now).expect_err("fs is exhausted");
    spend
        .try_spend("search", 1, now)
        .expect("the budget is PER UPSTREAM: search still has its own");
}
