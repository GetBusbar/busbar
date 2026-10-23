//! `cargo xtask loom` — the targeted loom model of the config-mutation swap invariant
//! (`crates/busbar-kernel/src/config/tests/txn_loom.rs`), the port of `scripts/loom.sh`.
//!
//! Loom explores thread interleavings exhaustively, so it is SLOW and deliberately NOT part of
//! `cargo test --workspace`: the module sits behind the optional `loom-model` feature and only this
//! command turns it on. `--release` because the exhaustive search runs much faster optimized (it is
//! NOT load-bearing for stack depth; see `LOOM_STACK_WORDS` in txn_loom.rs).
//!
//! NO PREEMPTION BOUND BY DEFAULT: the full, unbounded search of this two-thread model completes in
//! well under a second, so a bound would only give up the tail of the state space. An explicit
//! `LOOM_MAX_PREEMPTIONS` in the environment is still honoured (cargo passes the environment
//! through), for bisecting a failure to its shallowest interleaving.
//!
//! BOTH packages, unit targets of each (`--bins --lib`): the models moved from the bin into the
//! engine lib once already, and a selector naming only one side would come back GREEN AND EMPTY on
//! the far side of such a move. THE COUNT FLOOR refuses a run that executed zero models: a filter
//! that matches nothing still exits 0.

use std::process::Command;

/// The models' count: the sum of every harness's `test result: ok. N passed`. A FAILED harness line
/// is not counted; its own exit status is what stops the run.
pub fn ran_count(output: &str) -> u64 {
    output
        .lines()
        .filter_map(|l| l.strip_prefix("test result: ok. "))
        .filter_map(|rest| {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            let after = &rest[digits.len()..];
            (!digits.is_empty() && after.starts_with(" passed"))
                .then(|| digits.parse::<u64>().ok())
                .flatten()
        })
        .sum()
}

/// THE COUNT FLOOR: `txn_loom.rs` holds exactly two models, the positive `transaction_never_loses_a_swap`
/// and its negative control `unsectioned_read_build_swap_loses_an_update`. A run that executed fewer
/// has lost one of them (the control going missing leaves the positive model unable to fail), so
/// one is not a pass. Adding a model raises this number in the same change.
pub const MIN_MODELS: u64 = 2;

/// The run, as one cargo command string (so `gate package-selectors` checks its selectors).
pub const RUN: &str = "cargo test --release -p busbar -p busbar-kernel --bins --lib --features loom-model txn_loom -- --nocapture";

/// The cargo arguments of the run; `extra` follows `--nocapture`, as the script's `"$@"` did.
pub fn cargo_args(extra: &[String]) -> Vec<String> {
    let mut a: Vec<String> = RUN.split_whitespace().skip(1).map(str::to_string).collect();
    a.extend(extra.iter().cloned());
    a
}

pub fn main(args: &[String]) -> i32 {
    let root = match crate::ctx::workspace_root() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("xtask: {e}");
            return 3;
        }
    };
    let out = match Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(cargo_args(args))
        .current_dir(&root)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("xtask loom: cargo did not start: {e}");
            return 3;
        }
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    println!("{text}");
    if !out.status.success() {
        return out.status.code().unwrap_or(1);
    }
    let ran = ran_count(&text);
    if ran < MIN_MODELS {
        eprintln!(
            "loom gate VACUOUS: the txn_loom filter matched {ran} test(s) across busbar + busbar-kernel; the floor is {MIN_MODELS}."
        );
        eprintln!(
            "The models moved or were renamed; point this command at their new home. A green run that"
        );
        eprintln!("executed nothing is not a pass.");
        return 1;
    }
    println!("loom gate: {ran} interleaving model(s) ran to completion");
    0
}

#[cfg(test)]
mod tests {
    use super::{cargo_args, ran_count, MIN_MODELS};

    /// THE VACUOUS RUN: a filter that selects nothing exits 0 and prints `0 passed`.
    #[test]
    fn a_run_that_selected_no_test_counts_zero() {
        let vacuous = "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 412 filtered out\n";
        assert_eq!(ran_count(vacuous), 0);
    }

    /// BOTH HARNESSES: the count is the sum, so one side emptying cannot hide behind the other.
    #[test]
    fn the_count_sums_every_harness() {
        let two = "test result: ok. 1 passed; 0 failed; 0 ignored\ntest result: ok. 2 passed; 0 failed; 0 ignored\n";
        assert_eq!(ran_count(two), 3);
    }

    #[test]
    fn a_failed_harness_line_is_not_counted() {
        assert_eq!(
            ran_count("test result: FAILED. 0 passed; 1 failed; 0 ignored\n"),
            0
        );
    }

    /// The floor itself: zero and one (a model or its control lost) refused, the full set accepted.
    #[test]
    fn the_floor_discriminates_zero_from_some() {
        assert!(ran_count("test result: ok. 0 passed; 0 failed\n") < MIN_MODELS);
        assert!(ran_count("test result: ok. 1 passed; 0 failed\n") < MIN_MODELS);
        assert!(ran_count("test result: ok. 2 passed; 0 failed\n") >= MIN_MODELS);
    }

    /// The floor is the number of `#[test]` models in `txn_loom.rs`, so a model added or removed
    /// there without moving the floor is red here.
    #[test]
    fn the_floor_is_the_models_in_the_loom_file() {
        let src = include_str!("../../crates/busbar-kernel/src/config/tests/txn_loom.rs");
        let models = src.matches("#[test]").count() as u64;
        assert_eq!(models, MIN_MODELS);
    }

    #[test]
    fn the_selector_names_both_sides_and_passes_extra_args_after_nocapture() {
        let a = cargo_args(&["--test-threads=1".to_string()]);
        let s = a.join(" ");
        assert!(s.starts_with("test --release -p busbar -p busbar-kernel --bins --lib --features loom-model txn_loom -- --nocapture"), "{s}");
        assert_eq!(a.last().map(String::as_str), Some("--test-threads=1"));
    }
}
