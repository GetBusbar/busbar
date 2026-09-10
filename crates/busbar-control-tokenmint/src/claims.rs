// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE TABLE, AS DATA: which paths this crate answers on, at what admission bar, and which
//! body runs each one.
//!
//! ## Why this is a table and not a `mount` function
//!
//! It used to be a function: core's `oauth_as::routes::mount` took a core router and wired
//! seven routes onto it, so the surface named a core router type, decided when it was mounted, and
//! core carried a line naming this protocol. [`ROUTES`] is the declaration; the composition reads
//! it and mounts it; the only thing that changes when a route is added is this table.
//!
//! ## The paths are SEGMENTS, anchored to the operator's issuer
//!
//! A path on this surface is derived from the OPERATOR'S ISSUER: a tenant-prefixed issuer
//! (`https://host/tenant`) mounts its endpoints under that prefix, so a table with literal absolute
//! paths would be right for one deployment. Each row therefore carries its segments as
//! [`PathSeg::Lit`] data and an [`Anchor`] saying where the issuer's own path goes — AFTER the
//! well-known segment for the RFC 8414 document (§3.1, the one everybody gets backwards), BEFORE
//! the segment for everything else. [`Route::path_of`] composes the two, and the crate's own test
//! proves that composition equals the path the [`Identity`] derived and the metadata document
//! advertises, so the mounted path and the advertised one cannot drift apart.
//!
//! ## The bars, and the one that looks wrong until you read the RFC
//!
//! | route | bar | why |
//! |---|---|---|
//! | metadata, JWKS | [`Bar::Open`] | RFC 8414 §3 and RFC 7517: read by a client that has no credential yet. |
//! | authorize | [`Bar::Open`] | A browser endpoint. The resource owner is authenticated by the consent screen. |
//! | token, register | [`Bar::Open`] | These carry OAuth's OWN client authentication, which `oauth-as` performs. |
//! | consent | [`Bar::Operator`] | The one route busbar authenticates itself, through its EXISTING operator chain. |
//!
//! [`Bar::Open`] is not an absence of authentication; it is authentication that belongs to a
//! different protocol. Those bodies never read busbar's governance state, and the consent bodies
//! never check a credential: the operator was identified before they ran.

use busbar_contract::grammar::PathSeg;

use crate::config::Identity;

/// The request method a row answers. Two values because this surface has two.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

/// The admission bar a row DECLARES — what the composition records in its route table and the
/// auth middleware enforces BEFORE the body runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Bar {
    /// The caller presents no busbar credential, by declaration.
    Open,
    /// The caller is the OPERATOR, identified by the node's existing operator chain before the body
    /// runs. There is no credential check inside the body, and there must not be.
    Operator,
}

/// Which body in [`crate::answer`] runs a row. A closed enum rather than a function pointer, so the
/// table is readable as DATA by a gate that does not link this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Handler {
    /// Hand the request to `oauth-as` and return what it answers, unchanged.
    Forward,
    /// Render the consent screen and open a session.
    ConsentScreen,
    /// Stake one approval and hand the browser back to `/authorize`.
    ConsentSubmit,
}

/// Where the issuer's own path component goes relative to the row's segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Anchor {
    /// `{issuer_path}/{segments}` — every endpoint but one.
    UnderIssuer,
    /// `/{segments}{issuer_path}` — RFC 8414 §3.1 puts the well-known segment BEFORE the issuer's
    /// path, not after it.
    BeforeIssuer,
}

/// One declared route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// The row's name, as the composition logs it.
    pub name: &'static str,
    /// The literal segments, without the issuer's path.
    pub segments: &'static [PathSeg],
    /// Where the issuer's path goes.
    pub anchor: Anchor,
    /// The method the row answers.
    pub method: Method,
    /// The admission bar the composition records and the middleware enforces.
    pub bar: Bar,
    /// The body that runs it.
    pub handler: Handler,
}

impl Route {
    /// This row's absolute path under `identity`, exactly as the composition mounts it.
    #[must_use]
    pub fn path_of(&self, identity: &Identity) -> String {
        let mut segs = String::new();
        for seg in self.segments {
            segs.push('/');
            match seg {
                PathSeg::Lit(s) => segs.push_str(s),
                // The table below is all literals; a variable segment would be a row this
                // surface does not have, and it renders as the grammar spells it.
                PathSeg::Var => segs.push_str("{}"),
                PathSeg::Tail => segs.push_str("{*}"),
            }
        }
        match self.anchor {
            Anchor::UnderIssuer => format!("{}{segs}", identity.issuer_path),
            Anchor::BeforeIssuer => format!("{segs}{}", identity.issuer_path),
        }
    }
}

/// **THE WHOLE SERVED SURFACE.** Seven rows, in mount order — the order the composition's route
/// table records, so a boot listing reads as the previous release's did.
///
/// The RFC 7591 registration row is UNCONDITIONAL: the 1.6.0 ruling is that all three registration
/// mechanisms are on whenever the surface is. The advertised `registration_endpoint` in
/// [`crate::policy::registration_config`] is likewise unconditional, so the metadata document and
/// this table cannot disagree about that path.
pub const ROUTES: &[Route] = &[
    Route {
        name: "metadata",
        segments: &[
            PathSeg::Lit(".well-known"),
            PathSeg::Lit("oauth-authorization-server"),
        ],
        anchor: Anchor::BeforeIssuer,
        method: Method::Get,
        bar: Bar::Open,
        handler: Handler::Forward,
    },
    Route {
        name: "jwks",
        segments: &[PathSeg::Lit("jwks")],
        anchor: Anchor::UnderIssuer,
        method: Method::Get,
        bar: Bar::Open,
        handler: Handler::Forward,
    },
    Route {
        name: "authorize",
        segments: &[PathSeg::Lit("authorize")],
        anchor: Anchor::UnderIssuer,
        method: Method::Get,
        bar: Bar::Open,
        handler: Handler::Forward,
    },
    Route {
        name: "token",
        segments: &[PathSeg::Lit("token")],
        anchor: Anchor::UnderIssuer,
        method: Method::Post,
        bar: Bar::Open,
        handler: Handler::Forward,
    },
    Route {
        name: "consent",
        segments: &[PathSeg::Lit("consent")],
        anchor: Anchor::UnderIssuer,
        method: Method::Get,
        bar: Bar::Operator,
        handler: Handler::ConsentScreen,
    },
    Route {
        name: "consent",
        segments: &[PathSeg::Lit("consent")],
        anchor: Anchor::UnderIssuer,
        method: Method::Post,
        bar: Bar::Operator,
        handler: Handler::ConsentSubmit,
    },
    Route {
        name: "register",
        segments: &[PathSeg::Lit("register")],
        anchor: Anchor::UnderIssuer,
        method: Method::Post,
        bar: Bar::Open,
        handler: Handler::Forward,
    },
];

#[cfg(test)]
#[path = "tests/claims_tests.rs"]
mod claims_tests;
