//! Tests for `ops.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{row_for, MethodRow, Wording, METHODS, OP_CLASSES};

/// Every method maps to a class the plane declares.
#[test]
fn every_method_names_a_declared_class() {
    for row in METHODS {
        assert!(
            OP_CLASSES.contains(&row.op),
            "method {} names an undeclared class {}",
            row.method,
            row.op
        );
    }
}

/// No method name appears twice, so a lookup has one answer.
#[test]
fn no_method_name_is_repeated() {
    for (i, row) in METHODS.iter().enumerate() {
        assert!(
            !METHODS[..i].iter().any(|r| r.method == row.method),
            "method {} is listed twice",
            row.method
        );
    }
}

/// Both spellings of one operation agree on its class and on whether it streams.
///
/// This is the property the module header claims: the wording is a fact, never a price. If the
/// two spellings ever disagreed here, a caller's choice of vocabulary would move the money.
#[test]
fn the_two_spellings_of_an_operation_agree() {
    for row in METHODS {
        let partner: Vec<&MethodRow> = METHODS
            .iter()
            .filter(|r| r.op == row.op && r.wording != row.wording)
            .collect();
        assert_eq!(
            partner.len(),
            1,
            "{} has {} partner spellings, not one",
            row.method,
            partner.len()
        );
        assert_eq!(
            partner[0].streaming, row.streaming,
            "the two spellings of {} disagree on streaming",
            row.op
        );
    }
}

/// The lookup is total over the table and answers nothing else.
#[test]
fn the_lookup_answers_the_table_and_nothing_else() {
    for row in METHODS {
        assert_eq!(row_for(row.method), Some(row));
    }
    assert_eq!(row_for("tasks/incinerate"), None);
    assert_eq!(row_for(""), None);
    // Case matters: the two spellings differ only in case for some operations, and a lookup
    // that folded case would answer the wrong wording.
    assert_eq!(row_for("MESSAGE/SEND"), None);
}

/// Every streaming method is one of the two the codec's own streaming test recognises.
///
/// The codec decides "does this stream" by looking for a `/stream` suffix or one of two names.
/// This asserts the same set from the other direction, so the two readings cannot drift apart
/// without a red here.
#[test]
fn the_streaming_set_matches_the_codecs_own_rule() {
    for row in METHODS {
        let by_the_codecs_rule = row.method.ends_with("/stream")
            || row.method == "tasks/resubscribe"
            || row.method == "SendStreamingMessage"
            || row.method == "SubscribeToTask";
        assert_eq!(
            row.streaming, by_the_codecs_rule,
            "{} disagrees with the codec's streaming rule",
            row.method
        );
    }
}

/// The wording names are stable, because they are written into facts the journal keeps.
#[test]
fn the_wording_names_are_stable() {
    assert_eq!(Wording::Slashed.as_str(), "slashed");
    assert_eq!(Wording::Verb.as_str(), "verb");
}
