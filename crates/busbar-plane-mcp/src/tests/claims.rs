//! Tests for `claims.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{
    CLAIMS, DEFAULT_METADATA, DEFAULT_MOUNT, SCHEME, SCHEME_ALTS, TRANSPORT_HTTP, TRANSPORT_SSE,
    TRANSPORT_STDIO,
};
use busbar_contract::grammar::Selector;
use busbar_mcp_codec::{
    codec::protected_resource_metadata_path, codec::PATH_MCP, PLANE_KEY, PROTO_DECL,
};

/// The default mount is the codec's own, and the discovery path is composed from it by the
/// codec's own composer.
///
/// Both are read as VALUES. This asked the same two questions of the server half's SOURCE once,
/// with `include_str!` over `../../busbar-mcp/src/…`, which coupled this crate to a sibling its
/// manifest does not name — so the plane could be neither built nor deleted on its own, and the
/// strong-form deletion gate could not see it. The mount and the composer are the codec's now,
/// and both halves call the one composer, so a served route and this claim cannot be two
/// different strings.
#[test]
fn the_default_mount_is_the_codecs_own() {
    assert_eq!(DEFAULT_MOUNT, PATH_MCP);
    assert_eq!(
        DEFAULT_METADATA,
        protected_resource_metadata_path(DEFAULT_MOUNT)
    );
}

/// The discovery path is a FUNCTION OF THE MOUNT, and this is the assertion that says the note
/// in the module header is still live.
///
/// The protected-resource metadata rule inserts the well-known segment between the origin and
/// the resource's own path,
/// so an operator who moves the mount moves the discovery document with it. If that composition
/// ever collapses into a constant — if the answer stops depending on its argument — this goes
/// red, and the note stops being true and should be deleted. A note that quietly outlives its
/// cause is worse than no note at all.
#[test]
fn the_mount_is_still_configured() {
    let moved = protected_resource_metadata_path("/elsewhere");
    assert_ne!(moved, DEFAULT_METADATA);
    assert!(moved.ends_with("/elsewhere"));
}

/// This plane's registry key is the codec's own.
#[test]
fn the_plane_key_is_the_codecs_own() {
    assert_eq!(
        <crate::McpPlane as busbar_contract::plane::PlaneMeta>::KEY,
        PLANE_KEY
    );
    // And the protocol declaration names the same thing, so the two halves of the codec agree
    // with the plane and with each other.
    assert_eq!(PROTO_DECL.name, PLANE_KEY);
}

/// Every claim names one of the three declared transports and nothing else.
#[test]
fn every_claim_names_a_declared_transport() {
    for c in CLAIMS {
        assert!(
            [TRANSPORT_HTTP, TRANSPORT_SSE, TRANSPORT_STDIO].contains(&c.transport),
            "a claim names the undeclared transport {}",
            c.transport
        );
    }
}

/// All three transports are claimed, because the codec serves on all three.
#[test]
fn all_three_transports_are_claimed() {
    for transport in [TRANSPORT_HTTP, TRANSPORT_SSE, TRANSPORT_STDIO] {
        assert!(
            CLAIMS.iter().any(|c| c.transport == transport),
            "{transport} is served and not claimed"
        );
    }
}

/// Every claim either declares the one scheme and its alternatives, or declares none.
///
/// The discovery document is the one open surface: no scheme, and therefore no alternatives.
/// The emptiness is what makes the authenticate step's narrowing check meaningful, because
/// there is nothing there to narrow DOWN to.
#[test]
fn every_claim_declares_one_scheme_or_none() {
    let mut open = 0usize;
    for c in CLAIMS {
        match c.scheme {
            Some(scheme) => {
                assert_eq!(scheme, SCHEME);
                assert_eq!(c.scheme_alternatives, SCHEME_ALTS);
            }
            None => {
                open += 1;
                assert!(c.is_anonymous());
                assert!(c.scheme_alternatives.is_empty());
            }
        }
        assert!(c.idempotency.is_none());
    }
    assert_eq!(open, 1, "the discovery document is the one open surface");
}

/// No declared alternative is the word "anonymous".
///
/// The absence of a credential is a property of the CLAIM, not one more thing a plane may
/// narrow to. This is the assertion that keeps the invented alternative from coming back.
#[test]
fn no_alternative_stands_in_for_having_no_credential() {
    for c in CLAIMS {
        assert!(!c.scheme_alternatives.contains(&"anonymous"));
    }
}

/// Two claims on one transport never name the same selector.
///
/// Within one plane a contest is settled by order, so a duplicate is not a boot refusal — it is
/// a claim that can never be reached, which is worse, because nothing complains about it.
#[test]
fn no_claim_is_unreachable() {
    for (i, later) in CLAIMS.iter().enumerate() {
        for earlier in &CLAIMS[..i] {
            assert!(
                !(earlier.transport == later.transport
                    && selector_eq(&earlier.selector, &later.selector)),
                "a claim on {} repeats one above it",
                later.transport
            );
        }
    }
}

/// Whether two selectors are literally the same selector.
fn selector_eq(a: &Selector, b: &Selector) -> bool {
    a == b
}
