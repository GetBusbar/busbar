//! The claims this plane makes over arriving bytes.
//!
//! A claim is the only way a plane names a transport, and it names it as a claim — never as a
//! connection. jev has two exact-path claims, both spoken over HTTP, both carrying a bearer
//! credential this plane never sees (the core gateway credential — see `plane.rs::authenticate`).

use busbar_contract::grammar::{Claim, Selector};

use crate::ops::{PATH_MODELS, PATH_SYSTEMONE};

/// The request transport both of this plane's claims are made against.
pub const TRANSPORT: &str = "http";

/// The credential scheme this plane's claims sit under.
///
/// One scheme, one alternative: the bearer credential the core gateway resolves. The plane never
/// narrows to anything else and never sees what is behind it.
pub const SCHEME: &str = "decision-inbound";

/// The alternative a unit may be narrowed to. Every jev request carries a bearer credential; there
/// is no anonymous surface (unlike A2A's discovery documents — jev's model catalogue still needs
/// caller identity, because it is billed per the provider's own account scoping).
pub const ALT_TOKEN: &str = "bearer";

/// The alternatives declared on both claims.
const SCHEME_ALTERNATIVES: &[&str] = &[ALT_TOKEN];

/// The claims this plane declares, in declaration order. Both are exact paths — jev names its
/// operation in the HTTP verb and the path, never a pattern — so there is no overlap between them
/// for a boot to arbitrate.
pub const CLAIMS: &[Claim] = &[
    Claim {
        transport: TRANSPORT,
        selector: Selector::ExactPath(PATH_SYSTEMONE),
        scheme: Some(SCHEME),
        scheme_alternatives: SCHEME_ALTERNATIVES,
        idempotency: None,
    },
    Claim {
        transport: TRANSPORT,
        selector: Selector::ExactPath(PATH_MODELS),
        scheme: Some(SCHEME),
        scheme_alternatives: SCHEME_ALTERNATIVES,
        idempotency: None,
    },
];

#[cfg(test)]
#[path = "tests/claims.rs"]
mod tests;
