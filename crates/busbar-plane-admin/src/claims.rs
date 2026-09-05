//! The claim this plane makes over arriving bytes.
//!
//! Every one of the table's verbs ismounted under one prefix, and this crate names it:
//! [`busbar_contract::surface::ADMIN_PREFIX`]. The prefix used to be transcribed here as a literal,
//! with a hand-written assertion over the copy that could not check the original, because a plugin
//! may name `busbar-contract` and nothing else in the workspace and the literal lived in a
//! kernel-side crate. It lives in the contract now, which is where closed structure a plane has to
//! claim belongs, and the kernel-side crate names the same constant.

use busbar_contract::grammar::{Claim, PathSeg, Selector};
use busbar_contract::surface::ADMIN_PREFIX;

/// The transport this plane's one claim is made against: plain HTTP request/response, never a
/// session transport (see [`crate::meta`] for why this plane does not implement `SessionPlane`).
pub const TRANSPORT: &str = "http";

/// The credential scheme this plane's claim authenticates under.
///
/// **Judgment call**: the design does not name a scheme key for the admin surface as it does for the
/// `llm` plane's `llm-key`. `admin-token` is chosen here as a coherent, self-describing name for the
/// bearer credential `busbar-core`'s admin contract already authenticates against; it is not the
/// literal string the pre-extraction admin listener used, since this crate has no access to that
/// listener's source.
const SCHEME: &str = "admin-token";

/// The one alternative this plane's claim may narrow to: a bearer credential. The admin surface has
/// never offered a second credential form for its own listener, so there is nothing to narrow among.
const SCHEME_ALTS: &[&str] = &["bearer"];

/// The segment pattern matching the whole admin surface, regardless of depth: `Lit("api")`,
/// `Lit("v1")`, `Lit("admin")`, then `Tail` to swallow every remaining segment. A `PrefixOneLevel`
/// selector was considered and rejected: it matches exactly one segment past the prefix, and most
/// admin paths (`/keys/{id}/rotate`, `/config/versions/{v}`) are more than one segment deep.
const ADMIN_PATTERN: &[PathSeg] = &[
    PathSeg::Lit("api"),
    PathSeg::Lit("v1"),
    PathSeg::Lit("admin"),
    PathSeg::Tail,
];

/// The pattern's three literal segments ARE the contract's prefix, checked at compile time.
///
/// A selector is a list of segments and the prefix is one string, so the two spellings cannot be
/// one value; this is what keeps them one path. It is not the assertion it replaces: that one
/// checked a hand-copy against itself, and this one checks the segments against the prefix they
/// claim to be.
const _: () = assert!(matches!(ADMIN_PREFIX.as_bytes(), b"/api/v1/admin"));

/// This plane's one claim.
///
/// One claim is enough: every one of the table's verbs isreached under the same prefix, decoded by
/// method-and-path dispatch inside `decode_ingress` rather than by a separate claim per operation.
/// Splitting the claim per verb would buy nothing — the kernel's overlap check is about which PLANE
/// a request routes to, not which operation, and every admin operation is unambiguously this plane's.
pub const CLAIMS: &[Claim] = &[Claim {
    transport: TRANSPORT,
    selector: Selector::PathPattern(ADMIN_PATTERN),
    scheme: Some(SCHEME),
    scheme_alternatives: SCHEME_ALTS,
    // No idempotency location: the admin surface's own `If-Match` optimistic-concurrency scheme is
    // a body/header concern the verbs unit enforces, not a client-supplied idempotency key this
    // plane's claim would declare.
    idempotency: None,
}];
