//! The hand-written scanner, the refusal table and the method-row lookup, pinned against mutation.
//!
//! ## Why this file exists
//!
//! Everything asserted here was already reachable from the plane's public steps, and every one of
//! these assertions was already *implied* by a test somewhere in this crate. What none of them had
//! was a case that could FAIL when the code underneath changed: a scanner driven only over bodies
//! with no whitespace, no escaped key and no nested object answers the same thing whether or not it
//! can handle any of those. A mutation run said so directly — the whitespace step, every escape arm
//! of the key comparison, the depth arithmetic of the value skipper and three rows of the refusal
//! table could all be broken without a single test noticing.
//!
//! So these are the inputs that DISCRIMINATE. Each one is chosen because there is a specific way of
//! getting it wrong that the rest of the suite reads as correct, and the comment on each says which.

use super::{key_is, refusal_render, skip_space, skip_value, string_at, McpPlane};
use crate::{jsonrpc, ops};
use busbar_contract::unit::RefusalReason;

/// A KEY IS COMPARED AGAINST WHAT IT SPELLS, over every escape this grammar has.
///
/// The comparison walks the key as written and turns each two-character escape into the character it
/// names. Each arm is a separate row of that table, and a missing arm does not fail loudly — it
/// falls through to "not this member", so the fact the key introduces is silently attributed to
/// nobody. A member whose name contains a tab is not exotic; it is what a client sends when it
/// spells a name the way its own serialiser spells it.
///
/// Asserted one escape at a time so a deletion names itself.
#[test]
fn every_escape_a_key_may_be_written_with_is_read_as_the_character_it_names() {
    // Left: the key exactly as it appears between the quotes on the wire. Right: what it spells.
    let rows: &[(&[u8], &str)] = &[
        (b"a\\\"b", "a\"b"),
        (b"a\\\\b", "a\\b"),
        (b"a\\/b", "a/b"),
        (b"a\\nb", "a\nb"),
        (b"a\\tb", "a\tb"),
        (b"a\\rb", "a\rb"),
        (b"a\\bb", "a\u{08}b"),
        (b"a\\fb", "a\u{0c}b"),
    ];
    for (written, spells) in rows {
        assert!(
            key_is(written, spells),
            "the key written {} spells {spells:?} and was not recognised as it",
            String::from_utf8_lossy(written)
        );
        // And it spells THAT and not merely something: the same bytes must not match a neighbour.
        assert!(
            !key_is(written, "a?b"),
            "the key written {} matched a name it does not spell",
            String::from_utf8_lossy(written)
        );
    }
}

/// An escape this grammar does NOT have is "not this member", not a half-read name.
///
/// The `\u` form is the case that matters: it is a real escape in the wider document grammar and no
/// key this plane looks for is spelled with one, so reading it as anything other than a refusal
/// would be attributing a fact to a member the server never named.
#[test]
fn an_escape_outside_the_table_matches_nothing() {
    assert!(!key_is(b"a\\u0041b", "aAb"));
    assert!(!key_is(b"a\\u0041b", "a\\u0041b"));
    // A trailing backslash has nothing after it to name a character.
    assert!(!key_is(b"ab\\", "ab\\"));
}

/// A key that BEGINS with an escape is read from its first byte.
///
/// The escape's second byte is found by stepping one past the backslash. Stepping the wrong way, or
/// not stepping at all, is invisible for every key whose escape sits in the middle — the walk has
/// already moved past zero by then. A key that opens with one is the case that reads the very first
/// position, which is the only position where "one forward" and "one back" are distinguishable
/// without also being out of bounds.
#[test]
fn a_key_that_opens_with_an_escape_is_read_from_its_first_byte() {
    assert!(key_is(b"\\nx", "\nx"));
    assert!(key_is(b"\\\\", "\\"));
    assert!(!key_is(b"\\nx", "nx"));
}

/// WHITESPACE IS STEPPED OVER FORWARDS, from wherever the walk had got to.
///
/// Starting the check away from zero is deliberate. The step is used at five places in the member
/// walk and only the first of them starts at the beginning, so a step that went backwards would be
/// caught at position zero by a bounds panic and nowhere else — it would simply return an earlier
/// position and the walk would re-read bytes it had already passed.
#[test]
fn whitespace_is_stepped_over_forwards_from_a_position_that_is_not_the_start() {
    assert_eq!(skip_space(b"x   y", 1), 4, "past the three spaces, to the y");
    assert_eq!(
        skip_space(b"x\t\r\n y", 1),
        5,
        "every character this grammar counts as space"
    );
    assert_eq!(skip_space(b"xy", 1), 1, "no space is no movement");
    assert_eq!(
        skip_space(b"x  ", 1),
        3,
        "space that runs to the end lands on the end"
    );
}

/// A STRING THAT IS NEVER CLOSED IS NOT A STRING, and asking for it does not walk off the end.
///
/// The scan is bounded by the length of the body. A bound that admitted the position one past the
/// end would index it, and the difference between the two only shows on a body whose final byte is
/// inside an unterminated string — which is exactly what a truncated frame looks like.
#[test]
fn an_unterminated_string_is_refused_rather_than_read_past_the_end() {
    assert_eq!(string_at(b"\"abc", 0), None);
    assert_eq!(string_at(b"\"", 0), None);
    assert_eq!(string_at(b"\"ab\"c", 0), Some((&b"ab"[..], 4)));
    assert_eq!(string_at(b"x", 0), None, "not a string at all");
}

/// A STRING VALUE IS STEPPED OVER WHOLE, punctuation inside it and all.
///
/// A value skipper that did not know strings would stop at the first comma it saw, and a comma
/// inside a quoted value is the ordinary case — it is in every list of words a client ever sends.
/// Stopping there ends the member early and reads the rest of the string as further members.
#[test]
fn a_string_value_is_stepped_over_whole_including_its_punctuation() {
    // Past the closing quote of `"a,b"`, which is position 5 — not position 2, where the comma is.
    assert_eq!(skip_value(b"\"a,b\",x", 0), Some(5));
    assert_eq!(skip_value(b"\"a}b\",x", 0), Some(5));
}

/// A NESTED OBJECT CLOSES ON ITS OWN BRACE, not on the first one the walk meets.
///
/// The depth counter is what tells an inner closing brace from the outer one. Reading the inner
/// brace as the end of the value stops the walk inside the object, and every member after it is
/// read as a member of the wrong object.
#[test]
fn a_nested_object_is_stepped_over_to_its_own_closing_brace() {
    // `{"a":{"b":1}}` ends at 13; the inner `}` is at 11 and must not end it.
    assert_eq!(skip_value(b"{\"a\":{\"b\":1}},", 0), Some(13));
    assert_eq!(skip_value(b"[[1],2],", 0), Some(7));
}

/// A COMMA INSIDE A VALUE IS NOT THE END OF THE VALUE.
///
/// Only a separator at the top level ends a member. A comma between two members of a nested object
/// belongs to that object, and treating it as the outer separator truncates the value.
#[test]
fn a_separator_only_ends_a_value_at_the_top_level() {
    // The comma at 6 is inside the object; the value ends at the brace, 13.
    assert_eq!(skip_value(b"{\"a\":1,\"b\":2},", 0), Some(13));
    // And a top-level comma does end it.
    assert_eq!(skip_value(b"12,\"x\"", 0), Some(2));
}

/// THE THREE REFUSALS THIS DIALECT NAMES SPECIFICALLY KEEP THEIR OWN ANSWERS.
///
/// The table's catch-all is a correct answer for a reason with no row of its own, which is exactly
/// why a row that goes missing is invisible: the caller still gets a well-formed refusal, just the
/// wrong one. A request that was too large and a request the node failed to serve are different
/// events, and a client that retries on one and not the other needs them told apart.
#[test]
fn each_reason_this_dialect_names_keeps_its_own_code_and_words() {
    let too_large = refusal_render(RefusalReason::BodyTooLarge);
    assert_eq!(
        too_large,
        (jsonrpc::CODE_INVALID_REQUEST, "the request is too large")
    );

    for reason in [
        RefusalReason::SchemeNotDeclared,
        RefusalReason::CredentialRejected,
        RefusalReason::SessionUnbound,
        RefusalReason::CredentialBudget,
    ] {
        assert_eq!(
            refusal_render(reason),
            (
                jsonrpc::CODE_INVALID_REQUEST,
                "the request did not carry usable authority"
            ),
            "{reason:?} is an authority refusal"
        );
    }

    assert_eq!(
        refusal_render(RefusalReason::NoDestination),
        (
            jsonrpc::CODE_UPSTREAM_UNAVAILABLE,
            "no server is reachable for this request"
        )
    );

    // And the rows are DISTINCT from the catch-all, which is the property a deleted row breaks.
    let catch_all = refusal_render(RefusalReason::InFlightCap);
    assert_ne!(too_large, catch_all, "too large is not the generic answer");
    assert_ne!(
        refusal_render(RefusalReason::NoDestination),
        catch_all,
        "nowhere to go is not the generic answer"
    );
    assert_ne!(
        refusal_render(RefusalReason::SchemeNotDeclared),
        catch_all,
        "no usable authority is not the generic answer"
    );
}

/// THE ROW A CLASS COMES FROM IS THE ROW WHOSE CLASS IT IS.
///
/// The lookup feeds the audit step's streaming verdict, and a lookup that answered "no row" or
/// answered with a NEIGHBOUR's row would still produce a well-formed record — one that classified
/// the ending of a streaming call as though it had not streamed. Asserted over the whole table so a
/// method added later is covered without anybody remembering to come back here.
#[test]
fn every_method_row_is_found_by_its_own_operation_class() {
    for row in ops::METHODS {
        let found = McpPlane::row_for_op(row.op)
            .unwrap_or_else(|| panic!("{} names a class with no row", row.method));
        assert_eq!(
            found.op, row.op,
            "{} was answered with the row for {}",
            row.method, found.method
        );
        assert_eq!(
            found.streaming, row.streaming,
            "{} was answered with a row whose streaming verdict differs",
            row.method
        );
    }
}

/// The table declares both streaming and non-streaming rows, so the verdict above can differ.
///
/// Without this the row test passes vacuously on a table that is all one kind, and the mutation it
/// is there to catch — answering every class with one fixed row — would survive again.
#[test]
fn the_method_table_declares_both_streaming_and_non_streaming_rows() {
    assert!(
        ops::METHODS.iter().any(|r| r.streaming),
        "no row streams, so the streaming verdict is untestable"
    );
    assert!(
        ops::METHODS.iter().any(|r| !r.streaming),
        "every row streams, so the streaming verdict is untestable"
    );
}
