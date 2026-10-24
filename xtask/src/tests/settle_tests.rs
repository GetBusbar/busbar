//! `cargo xtask gate --settle`: every property the merge train relies on, each proven by a plant
//! the settle must answer the one right way (BUSBAR-1.6.0.md Law 9: a ceiling only falls to its
//! measure and a floor only rises to it).

use super::*;

fn holds(name: &str) {
    let (_, case) = CASES
        .iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("no settle case `{name}`"));
    case().unwrap_or_else(|e| panic!("{name}: {e}"));
}

#[test]
fn a_ceiling_the_measure_would_raise_is_refused() {
    holds("refuses-to-raise-a-ceiling");
}

#[test]
fn a_floor_the_measure_would_lower_is_refused() {
    holds("refuses-to-lower-a-floor");
}

#[test]
fn one_loosening_row_refuses_the_whole_settle() {
    holds("refuses-wholesale");
}

#[test]
fn only_the_listed_fields_change_and_every_other_byte_stays() {
    holds("touches-only-listed-fields");
}

#[test]
fn a_field_outside_the_listed_files_is_refused() {
    holds("refuses-a-file-off-the-list");
}

#[test]
fn a_row_two_entries_match_is_never_guessed() {
    holds("refuses-an-ambiguous-row");
}

#[test]
fn a_second_settle_is_a_no_op() {
    holds("idempotent");
}

#[test]
fn the_appended_clause_is_exact_and_the_prose_before_it_is_kept() {
    holds("the-clause-is-exact");
}

#[test]
fn the_selftest_runs_every_case() {
    assert_eq!(selftest(), Ok(CASES.len()));
}

/// The spelling: `gate --settle [--selftest]`, and nothing else beside it.
#[test]
fn the_cli_spelling_takes_no_gate_name_and_no_other_flag() {
    let run =
        |a: &[&str]| crate::cli::main(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
    assert_eq!(run(&["gate", "--settle", "--selftest"]), 0);
    assert_eq!(run(&["gate", "--settle", "segregation"]), 2);
    assert_eq!(run(&["gate", "--settle", "--strict"]), 2);
    assert_eq!(run(&["gate", "--settle", "--frobnicate"]), 2);
}
