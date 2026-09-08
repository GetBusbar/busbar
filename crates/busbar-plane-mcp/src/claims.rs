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

/// Whether `key` is the locally-launched-server claim key above.
///
/// A NAMED QUESTION rather than a comparison at each call site, and the naming is the whole point.
/// These constants are `&str` CLAIM KEYS — the vocabulary a claim is made against — and not the
/// engine's `Transport` axis, but they are spelled with the word "transport" in them, so every
/// `if transport == claims::TRANSPORT_STDIO` reads to a type-blind reader (and to the axis lint,
/// which is one) as the agnostic core forking on the wire carrier it is forbidden to see. Asking
/// the question by name states what is actually being asked, and leaves exactly one line in the
/// tree that compares against this constant: this one, in the plane that owns it.
#[must_use]
pub fn is_stdio(key: &str) -> bool {
    key == TRANSPORT_STDIO
}

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

/// Whether this plane declares a claim on `key`.
///
/// A NAMED QUESTION on the plane's own declaration, for the same reason `is_stdio` above is one.
/// The arrival step must establish that the claim it was handed is one of THIS plane's — a plane
/// may not answer a unit on a surface it never declared — and the only honest source for that
/// answer is the claim table itself. Asked at the call site it reads as `claim.transport ==
/// <something>`: an agnostic caller comparing against a wire carrier, which is the shape the axis
/// lint exists to catch and which a type-blind reader cannot tell apart from the real thing. Asked
/// here it is what it actually is — a lookup in the declaration — and it leaves exactly one line in
/// the tree that compares a claim's transport, in the plane that owns the claims.
#[must_use]
pub fn declares(key: &str) -> bool {
    CLAIMS.iter().any(|c| c.transport == key)
}

/// The claim one arrival was matched by, in the table's own most-specific-first order.
///
/// A NAMED QUESTION on the plane's own declaration, for the reason [`declares`] above is one, and it
/// answers the thing a transport alone cannot: two of this plane's four claims are made over the
/// SAME carrier and one of them carries no credential scheme. So "does this arrival's claim declare
/// a scheme" is a question about the ADDRESS as well as the carrier, and a caller that asked by
/// carrier alone would demand a credential on the discovery document — closing the one surface a
/// client reads in order to find out how to authenticate.
///
/// Matched by the grammar's own shapes and nothing else: an exact path is an equality and a stream
/// name is an equality. There is no prefix arm and its absence is the point — `/mcpx` is somebody
/// else's address, and a `starts_with` would take it. Every other way a plane can select bytes is
/// not something a path names, so nothing matches it; written as an arm rather than a wildcard so a
/// shape the grammar gains has to be considered here.
///
/// The order is the table's, which is most specific first: the discovery document sits above the
/// request surface precisely so a looser claim cannot swallow it, and the first match is the answer.
#[must_use]
pub fn matching(transport: &str, path: &str) -> Option<&'static Claim> {
    CLAIMS.iter().find(|c| {
        c.transport == transport
            && match c.selector {
                busbar_contract::grammar::Selector::ExactPath(exact) => exact == path,
                busbar_contract::grammar::Selector::StreamName(name) => name == path,
                _ => false,
            }
    })
}

/// Whether the claim this arrival was matched by declares a credential scheme at all.
///
/// The one reading a composition root needs off [`matching`], named so the root asks the plane its
/// own question rather than reaching into a `Claim`'s fields. An address no claim of this plane
/// matches declares nothing, which is the fail-closed reading in the only direction that matters
/// here: no scheme means no narrowing and no audience, and the arrival step has already refused a
/// carrier no claim names.
#[must_use]
pub fn declares_scheme(transport: &str, path: &str) -> bool {
    matching(transport, path).is_some_and(|c| c.scheme.is_some())
}

#[cfg(test)]
#[path = "tests/claims.rs"]
mod tests;
