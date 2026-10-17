//! The ledger's rule that a recorded finding is ANSWERED, never merely contradicted.
//!
//! A `findings` round at a tree stands until a fix is stamped or two zero rounds follow it at one
//! tree, from two auditors who are neither each other nor the one who found it. One zero at the
//! same tree is a disagreement, and a disagreement is not a closure: the scope reads `open`, and
//! `--check` holds it there at the finding's own severities.

use super::*;

const HASH: &str = "aaaa";
const OLD: &str = "bbbb";

fn scope(json: &str) -> Json {
    json_lite::parse(json).expect("the test fixture is valid JSON")
}

/// One round, in the shape `record` appends.
fn round(n: i64, result: &str, auditor: &str, hash: &str, counts: &str) -> String {
    format!(
        r#"{{"round": {n}, "result": "{result}", "auditor": "{auditor}", "audited_at": "c0",
             "tree_hash": "{hash}", "counts": {counts}, "report": "r"}}"#
    )
}

/// A scope whose top-level record is its last round, as `record` leaves it.
fn scope_of(rounds: &[String]) -> Json {
    let last = scope(rounds.last().expect("at least one round"));
    let mut sc = last.as_object().expect("a round is an object").clone();
    sc.insert("id", Json::Str("crates/k/src".to_string()));
    sc.insert("kind", Json::Str("production".to_string()));
    sc.insert("fixed_at", Json::Null);
    sc.insert(
        "rounds",
        Json::Array(rounds.iter().map(|r| scope(r.as_str())).collect()),
    );
    Json::Object(sc)
}

const HIGH: &str = r#"{"HIGH": 1}"#;
const NONE: &str = "{}";

/// XA1#1 RED: ONE ZERO AT THE SAME TREE IS NOT AN ANSWER. Before this, the newest verdict at the
/// current hash decided alone, so `record --result zero` by anybody turned an unfixed HIGH into
/// `unconfirmed`, which no rule of `--check` reds.
#[test]
fn one_zero_at_the_same_tree_does_not_answer_a_finding() {
    let sc = scope_of(&[
        round(1, "findings", "alice", HASH, HIGH),
        round(2, "zero", "bob", HASH, NONE),
    ]);
    assert_eq!(
        status_of(&sc, Some(HASH)),
        "open",
        "one contradicting zero leaves the finding standing"
    );
}

/// XA1#1 RED: THE FINDER IS NOT ONE OF THE TWO. Before this, the finder's own zero plus one other
/// auditor's made the scope `clean` over a HIGH nobody fixed.
#[test]
fn the_finder_and_one_other_cannot_answer_a_finding() {
    let sc = scope_of(&[
        round(1, "findings", "alice", HASH, HIGH),
        round(2, "zero", "Alice ", HASH, NONE),
        round(3, "zero", "bob", HASH, NONE),
    ]);
    assert_eq!(
        status_of(&sc, Some(HASH)),
        "open",
        "the auditor who found it cannot withdraw it, and one other reader is one"
    );
}

/// XA1#1 RED: A MOVED TREE AND ONE ZERO IS STILL ONE ZERO.
#[test]
fn one_zero_at_a_moved_tree_does_not_answer_a_finding() {
    let sc = scope_of(&[
        round(1, "findings", "alice", OLD, HIGH),
        round(2, "zero", "bob", HASH, NONE),
    ]);
    assert_eq!(status_of(&sc, Some(HASH)), "open");
}

/// The positive control: two other auditors reading one tree after the finding, each finding
/// nothing, is the answer, at the finding's own tree or at the tree the code has moved to.
#[test]
fn two_other_auditors_at_one_tree_answer_a_finding() {
    let same = scope_of(&[
        round(1, "findings", "alice", HASH, HIGH),
        round(2, "zero", "bob", HASH, NONE),
        round(3, "zero", "carol", HASH, NONE),
    ]);
    assert_eq!(status_of(&same, Some(HASH)), "clean");

    let moved = scope_of(&[
        round(1, "findings", "alice", OLD, HIGH),
        round(2, "zero", "bob", HASH, NONE),
        round(3, "zero", "carol", HASH, NONE),
    ]);
    assert_eq!(status_of(&moved, Some(HASH)), "clean");
}

/// Two zeros at two DIFFERENT trees are two single readings, not one confirmed one.
#[test]
fn two_zeros_at_two_trees_do_not_answer_a_finding() {
    let sc = scope_of(&[
        round(1, "findings", "alice", HASH, HIGH),
        round(2, "zero", "bob", OLD, NONE),
        round(3, "zero", "carol", HASH, NONE),
    ]);
    assert_eq!(status_of(&sc, Some(HASH)), "open");
}
