//! Tests for `plane.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{finish_of, member_of, refusal_render, sampling_destination, Codec};
use busbar_contract::dest::DestinationFacts;
use busbar_contract::unit::{AbortBy, FailureReason, RefusalReason, Step, UnitEnd};

/// The nested destination a sampling request reaches is the declared pair, and it is the SAME
/// value on both steps -- `verify` seals it and `route` dials it out of one expression, so a
/// change to either constant moves both or neither.
#[test]
fn verify_and_route_reach_one_declared_sampling_destination() {
    assert_eq!(
        sampling_destination(),
        DestinationFacts::NestedPlane {
            plane: crate::meta::SAMPLING_PLANE,
            op: crate::meta::SAMPLING_OP,
        }
    );
    let DestinationFacts::NestedPlane { plane, op } = sampling_destination() else {
        panic!("a sampling request is answered by another plane, not by anything else");
    };
    assert_eq!(plane, "llm");
    assert_eq!(op.as_str(), "chat");
}

/// Every closed refusal reason has an answer, and every answer is a code this plane may write.
///
/// Totality is the point: a reason with no row would be a caller who is told nothing, and the
/// contract's reason list is closed precisely so this can be checked rather than hoped for.
#[test]
fn every_refusal_reason_has_an_answer() {
    let reasons = [
        RefusalReason::InFlightCap,
        RefusalReason::CursorBudget,
        RefusalReason::CredentialBudget,
        RefusalReason::SessionBudget,
        RefusalReason::BodyTooLarge,
        RefusalReason::OpenSlotBusy,
        RefusalReason::SchemeNotDeclared,
        RefusalReason::CredentialRejected,
        RefusalReason::SessionUnbound,
        RefusalReason::Revoked,
        RefusalReason::ScopeMissing,
        RefusalReason::Vetoed,
        RefusalReason::NoDestination,
        RefusalReason::OverBudget,
        RefusalReason::GroupFrozen,
        RefusalReason::Unpriced,
        RefusalReason::OverdraftCeiling,
        RefusalReason::StaleSlice,
        RefusalReason::DurabilityUnavailable,
        RefusalReason::TierMismatch,
    ];
    for reason in reasons {
        let (code, message) = refusal_render(Step::Route, reason);
        assert!(
            crate::jsonrpc::CODES.contains(&code),
            "{reason:?} renders unknown code {code}"
        );
        assert!(
            !crate::jsonrpc::RETIRED_CODES.contains(&code),
            "{reason:?} renders the retired code {code}"
        );
        assert!(!message.is_empty(), "{reason:?} renders no words");
    }
}

/// A METHOD THIS SERVER DOES NOT ANSWER IS A `-32601`, not an internal error.
///
/// The gap this cell closes: every decode refusal fell to the catch-all arm and rendered `-32603`
/// with "the request could not be served at this time". That sentence tells a caller the SERVER
/// broke, when what happened is that the caller named a method the server does not implement — and
/// the two are acted on differently by every client written against this protocol, because one is
/// retried and the other is not.
///
/// The code is the one the legacy router answers an unimplemented method with, read from the codec
/// through `jsonrpc::CODE_METHOD_NOT_FOUND` rather than written here as a number: a code spelled on
/// both sides of a seam is a code the two sides can come to disagree about.
#[test]
fn a_method_this_server_does_not_answer_renders_method_not_found() {
    let (code, message) = refusal_render(Step::Decode, RefusalReason::DecodeFailed);
    assert_eq!(
        code,
        crate::jsonrpc::CODE_METHOD_NOT_FOUND,
        "a decode refusal renders {code}, which is not the code this protocol answers an \
         unimplemented method with"
    );
    assert!(
        !message.is_empty(),
        "the method-not-found arm renders no words"
    );
}

/// THE ARENA BUDGET STAYS INTERNAL, at the same step.
///
/// The decode step can refuse for two unrelated things: an address this server does not answer, and
/// a bound this node reached. Only the first is the caller's to fix, and folding the second into the
/// method-not-found arm would tell a caller its method does not exist on a node that ran out of
/// room — which is the same class of lie the `-32603` was, pointing the other way.
#[test]
fn a_bound_this_node_reached_is_not_a_method_that_does_not_exist() {
    let (code, _) = refusal_render(Step::Decode, RefusalReason::ArenaBudget);
    assert_ne!(code, crate::jsonrpc::CODE_METHOD_NOT_FOUND);
    assert_eq!(code, crate::jsonrpc::CODE_INTERNAL);
}

/// The step is read, not ignored: the same reason at a later step is not a method-not-found.
///
/// `DecodeFailed` is a reason the loop can carry past its own decode step — the journal keeps it on
/// the row whatever step ended the unit — and a unit that got as far as Route has already had its
/// method matched to a row. Rendering `-32601` for one would tell a caller a method it just used
/// does not exist.
#[test]
fn the_same_reason_at_a_later_step_is_not_a_method_that_does_not_exist() {
    for step in [Step::Route, Step::Meter, Step::Encode] {
        let (code, _) = refusal_render(step, RefusalReason::DecodeFailed);
        assert_ne!(
            code,
            crate::jsonrpc::CODE_METHOD_NOT_FOUND,
            "{step:?} renders a decode reason as a method that does not exist"
        );
    }
}

/// A refusal tells the caller nothing about the money.
#[test]
fn a_refusal_leaks_nothing_about_the_money() {
    for reason in [
        RefusalReason::OverBudget,
        RefusalReason::GroupFrozen,
        RefusalReason::Unpriced,
        RefusalReason::OverdraftCeiling,
        RefusalReason::StaleSlice,
    ] {
        let (_, message) = refusal_render(Step::Route, reason);
        for leak in ["budget", "bucket", "frozen", "price", "slice", "overdraft"] {
            assert!(
                !message.to_ascii_lowercase().contains(leak),
                "{reason:?} leaks {leak}"
            );
        }
    }
}

/// A held stream ends a turn when it completes; a single answer is complete.
#[test]
fn a_held_stream_ends_a_turn() {
    assert_eq!(
        finish_of(&UnitEnd::Completed, true),
        busbar_contract::unit::FinishClass::TurnComplete
    );
    assert_eq!(
        finish_of(&UnitEnd::Completed, false),
        busbar_contract::unit::FinishClass::Complete
    );
}

/// Who ended it decides how it ended.
#[test]
fn who_ended_it_decides_how_it_ended() {
    assert_eq!(
        finish_of(&UnitEnd::Aborted(AbortBy::Client), false),
        busbar_contract::unit::FinishClass::Partial
    );
    assert_eq!(
        finish_of(
            &UnitEnd::Failed {
                step: Step::Route,
                reason: FailureReason::Transport
            },
            false
        ),
        busbar_contract::unit::FinishClass::Error
    );
}

/// A metadata member whose name carries separators is read by name, not by pointer.
///
/// This is the case a pointer cannot express: the key itself contains the character a pointer
/// uses to mean "one level down", so a pointer naming it would read it as three levels.
#[test]
fn a_member_whose_name_carries_separators_is_read() {
    let block = br#"{"io.modelcontextprotocol/protocolVersion":"2026-07-28","other":1}"#;
    assert_eq!(
        member_of(block, "io.modelcontextprotocol/protocolVersion"),
        Some("2026-07-28")
    );
    assert_eq!(member_of(block, "io.modelcontextprotocol/clientInfo"), None);
}

/// A member of a nested object is not a member of the block.
///
/// The scan used to be for the quoted name anywhere in the block's bytes, so the first thing
/// that LOOKED like the member won — a nested object's own key, or the name written inside
/// somebody else's string value. Either one hands a later step a value the caller never put at
/// that name, and the progress token in particular is a correlation.
#[test]
fn a_nested_or_quoted_decoy_is_not_read_as_the_member() {
    let nested = br#"{"inner":{"progressToken":"decoy"},"progressToken":"real"}"#;
    assert_eq!(member_of(nested, "progressToken"), Some("real"));

    let quoted =
        br#"{"note":"the \"progressToken\":\"decoy\" is only prose","progressToken":"real"}"#;
    assert_eq!(member_of(quoted, "progressToken"), Some("real"));

    let only_nested = br#"{"inner":{"progressToken":"decoy"}}"#;
    assert_eq!(member_of(only_nested, "progressToken"), None);

    let suffix = br#"{"notTheProgressToken":"decoy"}"#;
    assert_eq!(member_of(suffix, "progressToken"), None);
}

/// A member that is present and is not a string reads as absent.
#[test]
fn a_member_that_is_not_a_string_reads_as_absent() {
    let block = br#"{"progressToken":42}"#;
    assert_eq!(member_of(block, "progressToken"), None);
}

/// A member spelled twice reads as the LAST one, which is what the server will read.
///
/// Every other reading of a body here goes through the span grammar, and the span grammar takes
/// the last occurrence because serde_json and the servers' own parsers do. This walk is the one
/// place a member is read WITHOUT the grammar — the block's keys carry separators a pointer
/// would read as levels — so it owes the same answer. Taking the first lets the client attribute
/// a fact to a value the server never sees: the progress token is a correlation, and a
/// correlation read off the losing duplicate answers a different request than the one that asked.
#[test]
fn a_member_spelled_twice_reads_as_the_last_one() {
    let block = br#"{"progressToken":"decoy","progressToken":"real"}"#;
    assert_eq!(member_of(block, "progressToken"), Some("real"));

    let three = br#"{"progressToken":"a","progressToken":"b","progressToken":"c"}"#;
    assert_eq!(member_of(three, "progressToken"), Some("c"));

    // The last one deciding also means a last one that is not a string reads as absent, however
    // many string-valued spellings came before it.
    let shadowed = br#"{"progressToken":"real","progressToken":42}"#;
    assert_eq!(member_of(shadowed, "progressToken"), None);

    // And a non-string first spelling does not blind the walk to the string that follows it.
    let recovered = br#"{"progressToken":42,"progressToken":"real"}"#;
    assert_eq!(member_of(recovered, "progressToken"), Some("real"));

    // The same for the separator-carrying name the block actually uses.
    let version = br#"{"io.modelcontextprotocol/protocolVersion":"old","io.modelcontextprotocol/protocolVersion":"new"}"#;
    assert_eq!(
        member_of(version, "io.modelcontextprotocol/protocolVersion"),
        Some("new")
    );
}

/// The codec state starts at nothing and counts up on both axes.
#[test]
fn the_codec_state_counts() {
    let mut codec = Codec::default();
    assert_eq!((codec.events_read, codec.rounds_asked), (0, 0));
    codec.events_read = codec.events_read.saturating_add(1);
    codec.rounds_asked = codec.rounds_asked.saturating_add(1);
    assert_eq!((codec.events_read, codec.rounds_asked), (1, 1));
}
