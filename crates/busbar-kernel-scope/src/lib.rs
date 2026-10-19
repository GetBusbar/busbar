// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-scope — the APPROVE step's scope half
//!
//! The kernel loop's approve step asks one question: does the principal hold enough scope for what
//! this operation needs? This crate is that question for the admin API: a small, pure data model
//! with no I/O, no wire format and no store, so it can be proven correct on its own.
//!
//! ## What is in here
//!
//! - [`Scope`] and [`Grants`] — the two-rung authorization chain and the set a principal holds,
//!   re-exported from their one home, `busbar_contract::authz`.
//! - [`admin_required_scope`] — THE admin-API scope matrix: derived from HTTP method and path alone
//!   (never the request body, so a crafted request cannot escalate). It is the only copy: the
//!   kernel's admin gate and the root's approve step both call it.
//! - The 66 operations that matrix was mechanically extracted from at the 1.5.5 tag are the
//!   oracle corpus's DATA (`testing/shadow-oracle/fixtures/openapi-1.5.5.json`, each operation's
//!   `x-busbar-required-scope`): the rule above is proven against every one of them, read from the
//!   1.5.5 document itself, instead of a hand-picked sample or a second copy here.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// The two-rung authorization chain and a principal's grant set, from their one home.
pub use busbar_contract::authz::{Grants, Scope};

/// The frozen Admin API v1 path prefix every admin operation is mounted under.
///
/// The contract's own, re-exported: the prefix is closed structure of the node's surface, and every
/// crate that has to name it names one literal.
pub use busbar_contract::surface::ADMIN_PREFIX;

/// `POST /config/validate` and `POST /plugins/inspect` — stateless dry-runs (reads in POST
/// clothing: the body is the config to lint / tarball to preview) that stay `read-only` although
/// every other mutation-shaped method needs `full`.
const READ_ONLY_POST_PATHS: &[&str] = &["/config/validate", "/plugins/inspect"];

/// The authorization matrix: the scope an admin endpoint requires, derived from METHOD + PATH —
/// never from the body. A strict two-rung split: every read (`GET`/`HEAD`) plus the two stateless
/// dry-run `POST`s is `read-only`; every mutation needs `full`. Unknown methods fail closed to
/// `full`.
///
/// Ported from 1.5.5's `admin_required_scope(method, path)`, behaviourally identical; `method` is a
/// plain string so this crate carries no HTTP-framework dependency. The kernel's admin gate
/// (`busbar_kernel::admin::gate::required_scope`) calls this function rather than restating it.
///
/// Three ways of being nearly-identical were each a defect when this matrix had a second copy, and
/// each is still the rule:
///
/// - **The method is compared EXACTLY.** `axum::http::Method`'s equality is case-sensitive, per
///   RFC 9110 §9.1: the method token is case-sensitive and `get` is not `GET` — it is an EXTENSION
///   method that happens to look like one. Case-folding it here let a non-canonical verb be folded
///   into `GET`/`HEAD` and DOWNGRADED to `read-only`, where 1.5.5 fails closed to `full`. That is the wrong direction for an authorization matrix to differ in, whatever else
///   filters the verb first.
/// - **The dry-run paths are matched on PATH ALONE**, with no method gate, exactly as the 1.5.5
///   matrix does. Requiring `POST` would answer `full` for a pair 1.5.5 answers `read-only`
///   for.
/// - **The query string is not part of the operation's identity.** The kernel gate hands
///   `uri().path()`; the root's approve step hands the request's recorded path, which carries
///   `?query` with it, so the query is cut here: `POST /config/validate?x=1` is the dry-run row,
///   as the previous release served it to a read-only token.
pub fn admin_required_scope(method: &str, path: &str) -> Scope {
    if method == "GET" || method == "HEAD" {
        return Scope::ReadOnly;
    }
    // Relative to the one true prefix, and without the query: the operation is the (method, path)
    // pair the table declares, and `?limit=4` never changes which row that is.
    let path = path.split_once('?').map_or(path, |(before, _)| before);
    let rel = path.strip_prefix(ADMIN_PREFIX).unwrap_or(path);
    if READ_ONLY_POST_PATHS.contains(&rel) {
        return Scope::ReadOnly;
    }
    Scope::Full
}

#[cfg(test)]
mod tests;
