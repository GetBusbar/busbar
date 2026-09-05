//! The claims this plane makes over arriving bytes.
//!
//! A claim is the only way a plane names a transport, and it names it as a claim — never as a
//! connection. Each claim carries exactly ONE selector, so the surface below is a list rather than a
//! route table: a boot that has to decide whether two claims could match the same bytes cannot do it
//! through an unexplained disjunction.
//!
//! ## The one thing that does not fit, said first
//!
//! This protocol's mount is CONFIGURED. An operator writes an absolute address for the deployment,
//! and the codec derives the path this plane is served at from that address's path — so two
//! deployments of the same build can serve it at two different paths. The contract's claim, on the
//! other hand, is an associated constant: a selector is a compile-time literal, read once at
//! registration and sealed into policy.
//!
//! Those two facts cannot both be honoured. What is declared below is the path the codec's own
//! documentation gives as the derivation's example and the one every fixture in the tree uses, and
//! that is stated here rather than hidden: a deployment that configures a different path is a
//! deployment this plane's claims do not cover, and the composition root must either constrain the
//! configuration or the contract must grow a way for a claim to name a configured value. It is a
//! finding, it is not fixed here, and it is the first thing the crate's notes record.

use busbar_contract::grammar::{Claim, Selector};

/// The request transport this plane's document claims are made against.
pub const TRANSPORT_HTTP: &str = "http";

/// The framing a streamed answer arrives on.
///
/// A streamed answer is the same request's own event framing rather than a second request, so the
/// claim is made against this key and the request is made against the one above.
pub const TRANSPORT_SSE: &str = "sse";

/// The transport a locally launched server speaks over.
pub const TRANSPORT_STDIO: &str = "stdio";

/// The credential scheme this plane's claims sit under.
///
/// One scheme with alternatives, not several schemes: which alternative a unit uses is the
/// authenticate step's answer, and a plane may only narrow within the set declared here.
const SCHEME: &str = "mcp-inbound";

/// The alternatives a unit may be narrowed to.
///
/// The bearer form is what a caller over the document transport presents. The environment form is
/// what a locally launched server is handed, because there is no request to carry a header on.
///
/// There is no third, anonymous form. There used to be one, invented as a scheme alternative
/// because a claim could not say "these units carry no credential" any other way — and a scheme
/// alternative meaning "none" is exactly what makes the authenticate step's narrowing check
/// toothless, because narrowing DOWN to it would pass. The discovery document says it in the one
/// place it belongs instead: its own claim declares no scheme.
const SCHEME_ALTS: &[&str] = &["bearer", "environment"];

/// The path this protocol is served at when the configured address has no other.
///
/// Named here as a constant so the one place it is written down is findable, and so the test that
/// pins it against the codec has something to compare.
pub const DEFAULT_MOUNT: &str = "/mcp";

/// The discovery document for the default mount.
pub const DEFAULT_METADATA: &str = "/.well-known/oauth-protected-resource/mcp";

/// The named stream a locally launched server's frames arrive on.
pub const STDIO_STREAM: &str = "mcp";

/// Build one claim over a selector on a named transport.
const fn claim(transport: &'static str, selector: Selector) -> Claim {
    Claim {
        transport,
        selector,
        scheme: Some(SCHEME),
        scheme_alternatives: SCHEME_ALTS,
        // No idempotency location is declared. The codec reads no client-supplied idempotency key
        // today, and declaring one here would change the shape of every request that reaches a
        // server, which is precisely the behaviour this crate is not allowed to change.
        idempotency: None,
    }
}

/// Build one claim whose units carry no credential at all.
///
/// Not "a scheme called anonymous": no scheme. The claim admits the anonymous principal without
/// consulting one, which is what a deliberately open surface actually is.
const fn open(transport: &'static str, selector: Selector) -> Claim {
    Claim {
        transport,
        selector,
        scheme: None,
        scheme_alternatives: &[],
        idempotency: None,
    }
}

/// The claims, most specific first.
///
/// The discovery document sits above the request surface because it is a longer, exact path and
/// because it is the one surface here that carries no credential; ordering it first is what keeps a
/// looser claim from swallowing it.
pub const CLAIMS: &[Claim] = &[
    // The discovery document is deliberately open: it is what a caller reads to find out how to
    // authenticate, so requiring a credential for it would be a closed loop.
    open(TRANSPORT_HTTP, Selector::ExactPath(DEFAULT_METADATA)),
    claim(TRANSPORT_HTTP, Selector::ExactPath(DEFAULT_MOUNT)),
    // The streamed answer arrives on the same path, framed as events.
    claim(TRANSPORT_SSE, Selector::ExactPath(DEFAULT_MOUNT)),
    // A locally launched server has no path at all: its frames arrive on a named stream.
    claim(TRANSPORT_STDIO, Selector::StreamName(STDIO_STREAM)),
];

#[cfg(test)]
mod tests {
    use super::{
        CLAIMS, DEFAULT_METADATA, DEFAULT_MOUNT, SCHEME, SCHEME_ALTS, TRANSPORT_HTTP,
        TRANSPORT_SSE, TRANSPORT_STDIO,
    };
    use busbar_contract::grammar::Selector;

    /// The default mount is the codec's own, and the discovery path is composed from it the same
    /// way the codec composes it.
    ///
    /// Both are read out of the codec's source, because both are visible to its own crate only. If
    /// the codec ever changes either, this goes red rather than the plane quietly claiming a path
    /// nothing is served at.
    #[test]
    fn the_default_mount_is_the_codecs_own() {
        let codec = include_str!("../../busbar-mcp/src/codec/mod.rs");
        assert!(
            codec.contains(&format!(r#"PATH_MCP: &str = "{DEFAULT_MOUNT}""#)),
            "the codec no longer names {DEFAULT_MOUNT} as its path"
        );
        let plane = include_str!("../../busbar-mcp/src/mcp/mod.rs");
        assert!(
            plane.contains(
                r#"PROTECTED_RESOURCE_WELL_KNOWN: &str = "/.well-known/oauth-protected-resource""#
            ),
            "the codec no longer names the discovery prefix"
        );
        assert!(
            plane.contains(r#"format!("{PROTECTED_RESOURCE_WELL_KNOWN}{mount_path}")"#),
            "the codec no longer composes the discovery path from the mount"
        );
        assert_eq!(
            DEFAULT_METADATA,
            format!("/.well-known/oauth-protected-resource{DEFAULT_MOUNT}")
        );
    }

    /// The mount is configured, and this is the assertion that says the finding is still live.
    ///
    /// If the codec ever stops deriving its mount from configuration — if the path becomes a
    /// constant — this goes red, and the note in the module header stops being true and should be
    /// deleted. A finding that quietly outlives its cause is worse than no note at all.
    #[test]
    fn the_mount_is_still_configured() {
        let plane = include_str!("../../busbar-mcp/src/mcp/mod.rs");
        assert!(
            plane.contains("let mount_path = normalise_path(path);"),
            "the mount is no longer derived from the configured address"
        );
    }

    /// This plane's registry key is the codec's own.
    #[test]
    fn the_plane_key_is_the_codecs_own() {
        assert_eq!(
            <crate::McpPlane as busbar_contract::plane::PlaneMeta>::KEY,
            busbar_mcp::PLANE_DECL.key
        );
        // And the protocol declaration names the same thing, so the two halves of the codec agree
        // with the plane and with each other.
        assert_eq!(busbar_mcp::PROTO_DECL.name, busbar_mcp::PLANE_DECL.key);
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
}
