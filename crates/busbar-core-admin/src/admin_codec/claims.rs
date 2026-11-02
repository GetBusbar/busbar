//! The claim this surface makes over arriving bytes.

use busbar_contract::grammar::{Claim, PathSeg, Selector};
use busbar_contract::surface::ADMIN_PREFIX;

/// The transport this surface's one claim is made against: plain HTTP request/response, never a

pub const TRANSPORT: &str = "http";

/// The credential scheme this surface's claim authenticates under.

const SCHEME: &str = "admin-token";

/// The one alternative this surface's claim may narrow to: a bearer credential. The admin surface has

const SCHEME_ALTS: &[&str] = &["bearer"];

/// The segment pattern matching the whole admin surface, regardless of depth: `Lit("api")`,

const ADMIN_PATTERN: &[PathSeg] = &[
    PathSeg::Lit("api"),
    PathSeg::Lit("v1"),
    PathSeg::Lit("admin"),
    PathSeg::Tail,
];

/// The pattern's three literal segments ARE the contract's prefix, checked at compile time.

const _: () = assert!(matches!(ADMIN_PREFIX.as_bytes(), b"/api/v1/admin"));

/// This surface's one claim.

pub const CLAIMS: &[Claim] = &[Claim {
    transport: TRANSPORT,
    selector: Selector::PathPattern(ADMIN_PATTERN),
    scheme: Some(SCHEME),
    scheme_alternatives: SCHEME_ALTS,

    idempotency: None,
}];
