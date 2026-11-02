//! Crate-level test suite for the admin surface's declarations.

use crate::admin_codec::verbs;

/// The combined table carries no duplicate verb name.
#[test]
fn combined_table_has_unique_verb_names() {
    let all = verbs::table();
    let mut names: Vec<&str> = all.iter().map(|e| e.verb).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(
        names.len(),
        before,
        "a verb name repeats in the combined table"
    );
}
