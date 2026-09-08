// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-control-oauth2 — busbar as an OAuth 2.1 authorization server, as a CONTROL SURFACE
//!
//! ## What this surface is for
//!
//! busbar already speaks OAuth as a RESOURCE server: an operator points it at Okta, Entra or Auth0,
//! and busbar refuses any token not minted for its own canonical URI. That covers the deployment
//! that has an identity provider and can get a client registered in it.
//!
//! The clients people actually run cannot do that. Codex, ChatGPT and Claude.ai discover an MCP
//! server, register themselves, and expect a token — and an enterprise identity team will not turn
//! on RFC 7591 dynamic registration to let them. So a gateway whose only OAuth answer is "point at
//! your IdP" cannot connect the agents its users already have. This surface closes that: with
//! `oauth_as:` configured, busbar IS the authorization server, and an agent that has never heard of
//! this deployment completes a login against it with nothing configured on either side.
//!
//! ## Why it is a CONTROL surface and not a plane
//!
//! There are two families of served things. A **data plane** (`llm`, `mcp`, `a2a`, `streams`) is
//! METERED and runs the full step list; a **control surface** (the admin API, and this) is
//! UNMETERED, declares its routes as data, and runs the control path — verify, admit, audit,
//! answer — and nothing else. An authorization server is squarely the second: nothing it does is
//! priced, nothing it does reaches upstream, and every one of its endpoints is a way of REACHING
//! busbar's controls or obtaining a credential rather than a way of spending money through it. See
//! `docs/design/PLUGIN-TREE.md`'s control-kind row and its rule — *a control surface declares
//! routes as data; no plugin names a transport* — which is what this crate is judged against.
//!
//! The consequence that matters for review: nothing in this crate meters, prices, records a
//! `PlaneRecord`, names a transport, names a plane, names a dialect, names a unit, or names
//! `busbar-core`. What it declares is a route table ([`claims`]); what it carries is the bodies
//! behind it ([`routes`]); what it holds is one running authorization server ([`surface`]).
//!
//! ## It costs nothing when it is not configured, and that is a property rather than an aspiration
//!
//! The crate is a NORMAL dependency of the composition, so the shipped binary can always serve this
//! surface and an operator never meets a config block the binary in front of them cannot honour.
//! What "off" means is that the composition holds no [`OAuth2Control`]: no
//! `oauth_as::server::AuthorizationServer` is constructed, no store is allocated, no signing key is
//! generated or read, no sweeper task is spawned, and no route is mounted — so the auth middleware
//! has nothing to consult and the route table has nothing to describe. That is the same posture
//! `mcp:` takes, and it is CHECKED by `busbar-core`'s `oauth_as/tests/mount_tests.rs`, which
//! subtracts the unconfigured route table from the configured one and requires the difference to be
//! exactly this surface's path inventory.
//!
//! ## The three registration mechanisms: ALL THREE ON, NO TOGGLES
//!
//! The `2026-07-28` MCP revision lists three ways a client obtains a `client_id`, in the order a
//! client should prefer them: pre-registration, **Client ID Metadata Documents**, and **Dynamic
//! Client Registration** — the last of which it marks *deprecated, retained for backwards
//! compatibility*. The 1.6.0 ruling is that busbar serves ALL THREE whenever `oauth_as:` is
//! configured, with no per-mechanism switches — the decision a reviewer can find is the config
//! block itself, and what makes always-on self-registration safe is that registration confers no
//! authority (the [`policy`] ceiling):
//!
//! * **Pre-registration**: the host provisions an `oauth_as::client::Client` into the store
//!   directly ([`OAuth2Control::server`]).
//! * **DCR** ([`policy`]) because it is what the clients shipping today actually speak. Declared
//!   UNCONDITIONALLY at `{issuer}/register`, and confined by a ceiling the registrant cannot move.
//! * **CIMD** ([`cimd`]) — the `SHOULD`. The seam is `Storage::get_client`: a `client_id` that
//!   names a document is fetched, validated (`client_id` equal to the URL, `redirect_uris` taken
//!   from the document and exact-matched against the request by `oauth-as`) and materialised as an
//!   ephemeral client under the SAME [`policy::default_grant_scopes`] ceiling registration uses.
//!
//!   **The FETCH is not this crate's.** That fetch is an SSRF surface by construction — the URL is
//!   attacker-supplied — and the resolve-then-pin guard that makes it safe belongs to the node, not
//!   to an authorization server: a control surface that carried its own copy of that guard would be
//!   the second copy of a security control in the tree, which is exactly the divergence-by-
//!   duplication failure mode the guard's own header warns about. So the fetch is a SEAM here
//!   ([`CimdFetch`]) and the composition installs the node's guarded one.
//!
//! ## What is deliberately NOT durable, said here rather than discovered
//!
//! The store is `oauth_as::store::MemoryStorage`. Authorization codes, tokens, refresh tokens and
//! registered clients therefore live in this process and are lost on restart. That is a REAL
//! limitation and not a placeholder pretending otherwise: a restarted deployment invalidates every
//! outstanding token and every dynamically registered client, and an agent connected to it has to
//! log in again. Closing it means implementing `oauth_as::store::Storage` over busbar's store
//! contract, whose `take_*` methods have to be atomic remove-and-return or refresh tokens
//! double-spend across nodes.

#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod cimd;
pub mod claims;
pub mod config;
pub mod consent;
pub mod meta;
pub mod policy;
pub mod routes;
pub mod signer;
pub mod surface;

pub use cimd::CimdFetch;
pub use config::{AsCfgError, AsIdentity, OauthAsCfg};
pub use routes::ControlRequest;
pub use surface::{spawn_sweeper, AsBuildError, OAuth2Control, SweepFault};

#[cfg(test)]
#[path = "tests/conformance.rs"]
mod conformance;
