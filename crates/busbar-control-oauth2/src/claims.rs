// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE TABLE, AS DATA: which paths this surface answers on, at what admission bar, and which
//! body runs each one.
//!
//! ## Why this is a table and not a `mount` function
//!
//! It used to be a function. `busbar_core::oauth_as::routes::mount` took a `CoreRouter` and wired
//! seven routes onto it, which meant three things at once: the surface named a core router type, the
//! surface decided when it was mounted, and core carried a line naming this protocol. The control-
//! kind rule in `docs/design/PLUGIN-TREE.md` — *a control surface declares routes as data; no
//! plugin names a transport* — closes all three. [`ROUTES`] is the declaration; the composition
//! reads it and mounts it; and the only thing that changes when a route is added is this table.
//!
//! Every row is `(endpoint, method, bar, handler)` and every one of the four is a value rather than
//! a call. The rows carry no PATH: a path on this surface is derived from the OPERATOR'S ISSUER at
//! mount time ([`Endpoint::path_of`]), because a tenant-prefixed issuer (`https://host/tenant`)
//! mounts its endpoints under that prefix, and a table with literal paths in it would be a table
//! that is right for one deployment.
//!
//! ## The bars, and the one that looks wrong until you read the RFC
//!
//! | route | bar | why |
//! |---|---|---|
//! | metadata, JWKS | [`Bar::Open`] | RFC 8414 §3 and RFC 7517: read by a client that has no credential yet. Requiring one is a discovery loop with no entrance. |
//! | authorize | [`Bar::Open`] | A browser endpoint. The resource owner is authenticated by the consent screen, and by nothing before it. |
//! | token, register | [`Bar::Open`] | These carry OAuth's OWN client authentication in the request, which `oauth-as` performs. busbar's data-plane bar knows nothing about a `client_secret_post` body and would refuse every conforming client. |
//! | consent | [`Bar::Operator`] | The one route here that busbar authenticates itself, through the EXISTING admin chain. See [`crate::consent`] on why the operator is the resource owner on this surface. |
//!
//! [`Bar::Open`] on five of the seven rows is not an absence of authentication; it is authentication
//! that belongs to a different protocol and is performed by the library that implements it. What it
//! does mean is that those handlers must never read anything from busbar's governance state, and
//! they do not: each one forwards bytes to `oauth-as` and returns what it answers.
//!
//! ## The rule this table exists to make checkable
//!
//! **A control surface answers on exactly the paths it declares here, and on no others.** The
//! `oauth-as` crate ships an `axum` feature that hands back a ready-made `Router`, and busbar does
//! not use it: that router is a single `fallback`, so its paths would enter the tree with no entry
//! in the composition's route table — and a served path the table does not describe is the one state
//! that table exists to make unrepresentable.

use crate::config::AsIdentity;

/// One endpoint this surface serves. The variant is the DECLARATION; the path is derived from the
/// operator's issuer by [`Endpoint::path_of`], so there is exactly one spelling of each path in the
/// process and the advertised endpoint and the mounted one cannot drift apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Endpoint {
    /// RFC 8414 authorization server metadata.
    Metadata,
    /// RFC 7517 JSON Web Key Set — the public half of the signing key.
    Jwks,
    /// RFC 6749 §3.1 authorization endpoint. A browser endpoint.
    Authorize,
    /// RFC 6749 §3.2 token endpoint.
    Token,
    /// The consent screen. busbar's own, not the library's.
    Consent,
    /// RFC 7591 dynamic client registration.
    Register,
}

impl Endpoint {
    /// This endpoint's path under `identity`, exactly as the composition mounts it and exactly as
    /// the metadata document advertises it.
    pub fn path_of(self, identity: &AsIdentity) -> &str {
        match self {
            Endpoint::Metadata => identity.metadata_path(),
            Endpoint::Jwks => identity.jwks_path(),
            Endpoint::Authorize => identity.authorize_path(),
            Endpoint::Token => identity.token_path(),
            Endpoint::Consent => identity.consent_path(),
            Endpoint::Register => identity.register_path(),
        }
    }
}

/// The request method a row answers. Two values because this surface has two; a third would be a
/// row, not a redesign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

/// The admission bar a row DECLARES — the value the composition hands its route table, and the one
/// the auth middleware enforces BEFORE the handler runs.
///
/// Two values and no third, and neither of them is an omission. See the table in the module header
/// for why five rows are [`Bar::Open`] and exactly one is [`Bar::Operator`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bar {
    /// The caller presents no busbar credential, by declaration.
    Open,
    /// The caller is the OPERATOR, identified by the node's existing admin chain before the handler
    /// runs. There is therefore no credential check inside the handler, and there must not be: a
    /// second opinion about who an operator is, held by the authorization server, is the exact
    /// duplication this surface was built not to have.
    Operator,
}

/// Which body in [`crate::routes`] runs a row.
///
/// A closed enum rather than a function pointer, because the table has to be readable as DATA by a
/// gate that does not link this crate: `PLUGIN-TREE.md`'s §2.5 rule is that a plugin DECLARES a
/// route and the composition mounts it, and a table of function pointers is a mount wearing a
/// different type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Handler {
    /// Hand the request to `oauth-as` and return what it answers, unchanged.
    /// ([`crate::routes::forward`])
    Forward,
    /// Render the consent screen and open a session. ([`crate::routes::consent_screen`])
    ConsentScreen,
    /// Stake one approval and hand the browser back to `/authorize`.
    /// ([`crate::routes::consent_submit`])
    ConsentSubmit,
}

/// One declared route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlRoute {
    /// Which endpoint the row is for; the path comes from [`Endpoint::path_of`].
    pub endpoint: Endpoint,
    /// The method the row answers.
    pub method: Method,
    /// The admission bar the composition records and the middleware enforces.
    pub bar: Bar,
    /// The body that runs it.
    pub handler: Handler,
}

/// **THE WHOLE SERVED SURFACE.** Seven rows, in mount order.
///
/// Mount order is preserved rather than sorted, because it is the order the route table records and
/// an operator reading a boot listing should see the same sequence a previous release printed.
///
/// The RFC 7591 registration row is UNCONDITIONAL: the 1.6.0 ruling is that all three registration
/// mechanisms are on whenever the surface is, with no toggles. The advertised
/// `registration_endpoint` in [`crate::policy::registration_config`] is likewise unconditional, so
/// the metadata document and this table cannot disagree about that path.
pub const ROUTES: &[ControlRoute] = &[
    ControlRoute {
        endpoint: Endpoint::Metadata,
        method: Method::Get,
        bar: Bar::Open,
        handler: Handler::Forward,
    },
    ControlRoute {
        endpoint: Endpoint::Jwks,
        method: Method::Get,
        bar: Bar::Open,
        handler: Handler::Forward,
    },
    ControlRoute {
        endpoint: Endpoint::Authorize,
        method: Method::Get,
        bar: Bar::Open,
        handler: Handler::Forward,
    },
    ControlRoute {
        endpoint: Endpoint::Token,
        method: Method::Post,
        bar: Bar::Open,
        handler: Handler::Forward,
    },
    ControlRoute {
        endpoint: Endpoint::Consent,
        method: Method::Get,
        bar: Bar::Operator,
        handler: Handler::ConsentScreen,
    },
    ControlRoute {
        endpoint: Endpoint::Consent,
        method: Method::Post,
        bar: Bar::Operator,
        handler: Handler::ConsentSubmit,
    },
    ControlRoute {
        endpoint: Endpoint::Register,
        method: Method::Post,
        bar: Bar::Open,
        handler: Handler::Forward,
    },
];
