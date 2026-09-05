//! The claim this plane makes over arriving bytes.
//!
//! `busbar-core`'s admin contract mounts every one of the 66+17 verbs under one prefix,
//! `busbar_substrate::api::ADMIN_PREFIX = "/api/v1/admin"`. This crate may depend on nothing but
//! `busbar-contract` (see the crate-root doc comment), so the prefix is not imported — it is
//! transcribed here as a literal, with this comment as the citation of where it is mirrored from.
//! **Flagged as a place the contract did not fit cleanly**: a shared literal transcribed by hand in
//! two crates is exactly the drift hazard the workspace's dependency-version table exists to close
//! for external crates, and there is no equivalent seam for a `&'static str` shared between a
//! kernel-side crate and a plugin crate that must not depend on it. See the report for this finding
//! stated plainly, rather than silently duplicating the literal without a comment.
const ADMIN_PREFIX_MIRROR: &str = "/api/v1/admin";

/// A boot-time assertion that this crate's mirrored literal has not silently drifted from its own
/// segment shape (three literal segments). This cannot check the OTHER copy — that is exactly the
/// finding above — but it does mean a typo introduced here fails immediately rather than at claim
/// overlap time.
const _: () = assert!(matches!(ADMIN_PREFIX_MIRROR.as_bytes(), b"/api/v1/admin"));

use busbar_contract::grammar::{Claim, PathSeg, Selector};

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

/// This plane's one claim.
///
/// One claim is enough: every one of the 66+17 verbs is reached under the same prefix, decoded by
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
