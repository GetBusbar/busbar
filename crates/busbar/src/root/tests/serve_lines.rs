//! Tests for `serve_lines.rs`: the line carrier is the transports' declared fact, never a name the
//! root holds.

use super::*;
use crate::root::linked::LinkedTransport;

/// A transport row whose claims are `claims` and whose first-line claims are `lines`, built never.
fn row(
    key: &'static str,
    claims: fn() -> Vec<&'static str>,
    lines: fn() -> Vec<&'static str>,
) -> LinkedTransport {
    LinkedTransport {
        key,
        composes_over: &[],
        build: |_, _| unreachable!("the carrier is read off the rows, never off a built wire"),
        claims,
        upgrades: Vec::new,
        lines,
        offered: crate::root::doors::offers_unstated,
    }
}

/// THE CARRIER IS WHAT THE ROWS DECLARE: the one claim whose row opens on the first line, whatever
/// it is called; a build with none carries no lines.
#[test]
fn the_line_carrier_is_the_claim_a_row_declares_opening_on_its_first_line() {
    let rows = [
        row(
            "framed-wire",
            || vec!["framed-wire", "framed-too"],
            Vec::new,
        ),
        row("pipe-wire", || vec!["pipe-wire"], || vec!["pipe-wire"]),
    ];
    assert_eq!(line_carrier(&rows), Ok(Some("pipe-wire")));
    assert_eq!(line_carrier(&rows[..1]), Ok(None));
    assert_eq!(line_carrier(&[]), Ok(None));
}

/// TWO LINE CARRIERS ARE REFUSED, naming both: the process has one stdin/stdout, and which claim it
/// carries is never decided by picking the first.
#[test]
fn two_claims_opening_on_their_first_line_are_refused() {
    let rows = [
        row("pipe-wire", || vec!["pipe-wire"], || vec!["pipe-wire"]),
        row("other-pipe", || vec!["other-pipe"], || vec!["other-pipe"]),
    ];
    let refusal = line_carrier(&rows).expect_err("two line carriers are ambiguous");
    assert!(refusal.contains("`pipe-wire`"), "{refusal}");
    assert!(refusal.contains("`other-pipe`"), "{refusal}");
}

/// The build's own carrier is read off its linked rows, and a build that links one serves it.
#[test]
fn the_builds_carrier_is_read_off_its_linked_rows() {
    assert_eq!(refusal(), None, "the build states one line carrier at most");
    assert_eq!(
        carrier(),
        line_carrier(crate::LINKED.transports).expect("one line carrier")
    );
    assert!(carrier().is_some(), "this build links a line carrier");
}

/// THE SESSION CREDENTIAL'S VARIABLE is spelled from the plane's key and the carrier's key, both
/// upper-cased: the shape the launching client's `env` block has always carried.
#[test]
fn the_credential_variable_is_spelled_from_the_plane_and_the_carrier() {
    assert_eq!(
        env_credential("tool-door", "pipe"),
        "BUSBAR_TOOL-DOOR_PIPE_CREDENTIAL"
    );
    assert_eq!(env_credential("x", "y"), "BUSBAR_X_Y_CREDENTIAL");
}
