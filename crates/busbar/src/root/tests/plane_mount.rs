//! Tests for `plane_mount.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.
//!
//! The two planes' own mount cells drive this body end to end through their own legs. What is here
//! is the part that belongs to NEITHER plane: the path walk over the closed grammar's shapes, and
//! the trailing-slash reading, which is the one normalisation this file makes and therefore the one
//! that has to be stated rather than assumed.

use super::*;

use busbar_contract::grammar::{PathSeg, Selector};

/// One claim over an exact path, for a walk that is about the matcher and not about any plane.
const fn exact(path: &'static str) -> Claim {
    Claim {
        transport: "http",
        selector: Selector::ExactPath(path),
        scheme: None,
        scheme_alternatives: &[],
        idempotency: None,
    }
}

/// **A trailing slash is the same address.**
///
/// `/mcp` and `/mcp/` are one address to every router in this tree and to every client of either
/// protocol. A mount that took the first and handed the second straight through would run one of
/// them past the loop and the other around it — the same request, gated or not depending on a
/// character — which is a hole an attacker types rather than finds.
#[test]
fn a_trailing_slash_names_the_same_address_and_a_prefix_does_not() {
    static CLAIMS: &[Claim] = &[exact("/mcp")];

    assert!(claims_a_path(CLAIMS, "/mcp"));
    assert!(claims_a_path(CLAIMS, "/mcp/"), "the same address");

    // And the near misses, which are the cell. A prefix is somebody else's path, a deeper path is a
    // different address, and a doubled slash is neither.
    assert!(!claims_a_path(CLAIMS, "/mcpx"));
    assert!(!claims_a_path(CLAIMS, "/mcp/x"));
    assert!(!claims_a_path(CLAIMS, "/mcp//"));
    assert!(!claims_a_path(CLAIMS, "/"));
    assert!(!claims_a_path(CLAIMS, ""));
}

/// **A declaration written with a trailing slash names the same address too.**
///
/// The normalisation is applied to BOTH sides, so a plane that declared `/mcp/` and a caller that
/// asked for `/mcp` meet. One-sided normalisation is the same hole with the character on the other
/// foot.
#[test]
fn the_normalisation_is_applied_to_the_declaration_as_well_as_the_request() {
    static CLAIMS: &[Claim] = &[exact("/mcp/")];
    assert!(claims_a_path(CLAIMS, "/mcp"));
    assert!(claims_a_path(CLAIMS, "/mcp/"));
    assert!(!claims_a_path(CLAIMS, "/mcpx"));
}

/// **The root is an address of its own and is never trimmed away.**
///
/// Trimming `/` would leave the empty string, which is not an address at all — and a claim on `/`
/// would then match nothing while looking like it matched everything.
#[test]
fn the_root_path_survives_normalisation() {
    assert_eq!(normalise("/"), "/");
    assert_eq!(normalise("/mcp/"), "/mcp");
    assert_eq!(normalise("/mcp"), "/mcp");
    static ROOT: &[Claim] = &[exact("/")];
    assert!(claims_a_path(ROOT, "/"));
}

/// **A selector that is not a path matches no path.**
///
/// A locally launched server's claim is made on a named stream, and a stream name is not an address
/// this listener carries. Matching one here would take a request off the mounted router because a
/// completely different carrier happened to use the same word.
#[test]
fn a_selector_that_is_not_a_path_matches_no_path() {
    static STREAM: &[Claim] = &[Claim {
        transport: "stdio",
        selector: Selector::StreamName("mcp"),
        scheme: None,
        scheme_alternatives: &[],
        idempotency: None,
    }];
    assert!(!claims_a_path(STREAM, "/mcp"));
    assert!(!claims_a_path(STREAM, "mcp"));
}

/// **A segment pattern is an address, not a prefix of one**, and a variable segment is never empty.
///
/// The empty-segment case is the one worth naming: `/a2a/agents/` would otherwise name an agent
/// whose identifier is the empty string, which is an address no router below serves.
#[test]
fn a_pattern_matches_one_address_and_not_its_prefixes() {
    static PATTERN: &[Claim] = &[Claim {
        transport: "http",
        selector: Selector::PathPattern(&[
            PathSeg::Lit("a2a"),
            PathSeg::Lit("agents"),
            PathSeg::Var,
        ]),
        scheme: None,
        scheme_alternatives: &[],
        idempotency: None,
    }];
    assert!(claims_a_path(PATTERN, "/a2a/agents/one"));
    assert!(
        claims_a_path(PATTERN, "/a2a/agents/one/"),
        "and the same address with a trailing slash"
    );
    assert!(!claims_a_path(PATTERN, "/a2a/agents"), "a collection");
    assert!(
        !claims_a_path(PATTERN, "/a2a/agents/"),
        "an identifier that is the empty string is not an identifier"
    );
    assert!(!claims_a_path(PATTERN, "/a2a/agents/one/two"), "deeper");
}

/// **Every ending is a status, and the two credential doors stay apart.**
///
/// A caller refused at Authenticate is told its credential was not accepted; one refused at Approve
/// or Verify is told the credential was accepted and does not cover this. Collapsing them sends a
/// caller with a bad token away to fix its permissions.
#[test]
fn the_two_credential_doors_are_two_statuses() {
    use busbar_contract::transport::Outcome as O;
    assert_eq!(status_of(O::Unauthenticated), 401);
    assert_eq!(status_of(O::Forbidden), 403);
    assert_ne!(status_of(O::Unauthenticated), status_of(O::Forbidden));
    assert_eq!(status_of(O::Completed), 200);
    for refused in [
        O::Unauthenticated,
        O::Forbidden,
        O::NotFound,
        O::Throttled,
        O::TimedOut,
        O::Unavailable,
    ] {
        assert!(
            status_of(refused) >= 400,
            "{refused:?} is not an answer a caller should read as success"
        );
    }
}
